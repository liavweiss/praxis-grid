//! Experimental [`AgentToAgentProvider`] controller.
//!
//! Reconciles placement and performs a bounded, side-effect-free Agent Card
//! GET after at least one site matches. A failed refresh retains the previous
//! bounded card for diagnostics but always publishes the current generation
//! as unavailable.

use std::{sync::Arc, time::Duration};

use k8s_openapi::api::core::v1::ObjectReference;
use kube::{
    Client, Resource as _,
    api::{Api, ListParams, Patch, PatchParams},
    runtime::{
        controller::Action,
        events::{Event, EventType, Recorder, Reporter},
    },
};

use crate::{
    crd::{
        agent_to_agent_provider::{AgentCardInfo, AgentToAgentProvider, AgentToAgentProviderStatus},
        grid_network::GridNetwork,
        grid_site::GridSite,
        inference_provider::ProviderPhase,
    },
    error::OperatorError,
    resources::{
        a2a_probe,
        credentials::{self, CredentialPlan, CredentialResolver as _, KubernetesSecretResolver},
        endpoint_tls,
    },
};

/// Periodic refresh interval for Agent Card discovery.
const REQUEUE_INTERVAL: Duration = Duration::from_secs(300);
/// Requeue interval after a transient controller error.
const ERROR_REQUEUE_INTERVAL: Duration = Duration::from_secs(30);
/// Total budget for DNS, Secret reads, TLS, and the Agent Card response.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Field manager used for status server-side apply.
const FIELD_MANAGER: &str = "grid-operator";

/// Desired status produced by one reconciliation.
struct DesiredStatus {
    /// Current provider phase.
    phase: ProviderPhase,
    /// Deterministically sorted matching site names.
    matching_sites: Vec<String>,
    /// Stable machine-readable failure reason.
    reason: Option<String>,
    /// Current or retained bounded Agent Card subset.
    discovered_card: Option<AgentCardInfo>,
}

/// Reconcile one [`AgentToAgentProvider`].
///
/// # Errors
///
/// Returns [`OperatorError`] when Kubernetes API access fails.
pub async fn reconcile(provider: Arc<AgentToAgentProvider>, client: Arc<Client>) -> Result<Action, OperatorError> {
    let name = provider
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| std::process::abort());
    tracing::debug!(name, "reconciling AgentToAgentProvider");

    let recorder = Recorder::new(
        client.as_ref().clone(),
        Reporter {
            controller: "agent-to-agent-provider-controller".into(),
            instance: None,
        },
    );
    let object_ref = provider.object_ref(&());
    let desired = Box::pin(resolve_desired_status(&provider, &client)).await?;
    Box::pin(update_status(&provider, &client, desired, &recorder, &object_ref)).await?;
    Ok(Action::requeue(REQUEUE_INTERVAL))
}

/// Requeue a failed reconciliation with a bounded delay.
pub fn error_policy(_provider: Arc<AgentToAgentProvider>, error: &OperatorError, _client: Arc<Client>) -> Action {
    tracing::error!(%error, "AgentToAgentProvider reconciliation failed");
    Action::requeue(ERROR_REQUEUE_INTERVAL)
}

/// Validate fields that require no Kubernetes API or network work.
pub(crate) fn validate_provider_config(provider: &AgentToAgentProvider) -> bool {
    !provider.spec.grid_network_ref.trim().is_empty()
        && a2a_probe::validate_discovery_config(&provider.spec.endpoint, provider.spec.agent_card.as_ref())
}

/// Apply `siteSelector.matchLabels` to sites from the referenced network.
pub(crate) fn sites_matching_selector(provider: &AgentToAgentProvider, sites: &[GridSite]) -> Vec<String> {
    let selector = &provider.spec.site_selector.match_labels;
    let mut names: Vec<String> = sites
        .iter()
        .filter(|site| {
            let labels = site.metadata.labels.as_ref();
            selector
                .iter()
                .all(|(key, value)| labels.is_some_and(|all| all.get(key).is_some_and(|found| found == value)))
        })
        .filter_map(|site| site.metadata.name.clone())
        .collect();
    names.sort();
    names
}

/// List sites belonging to one Grid network.
async fn list_sites_for_network(client: &Client, network_ref: &str) -> Result<Vec<GridSite>, OperatorError> {
    let api = Api::<GridSite>::all(client.clone());
    let sites = Box::pin(api.list(&ListParams::default())).await?;
    Ok(sites
        .items
        .into_iter()
        .filter(|site| site.spec.grid_network_ref == network_ref)
        .collect())
}

/// Resolve static configuration, network, placement, credentials, and card.
async fn resolve_desired_status(
    provider: &AgentToAgentProvider,
    client: &Client,
) -> Result<DesiredStatus, OperatorError> {
    let previous = provider
        .status
        .as_ref()
        .and_then(|status| status.discovered_card.clone());
    if !validate_provider_config(provider) {
        return Ok(unavailable(Vec::new(), "ProviderConfigInvalid", previous));
    }
    let networks = Api::<GridNetwork>::all(client.clone());
    if Box::pin(networks.get_opt(&provider.spec.grid_network_ref))
        .await?
        .is_none()
    {
        return Ok(unavailable(Vec::new(), "GridNetworkNotFound", previous));
    }
    let sites = Box::pin(list_sites_for_network(client, &provider.spec.grid_network_ref)).await?;
    let matching_sites = sites_matching_selector(provider, &sites);
    if matching_sites.is_empty() {
        return Ok(DesiredStatus {
            phase: ProviderPhase::Pending,
            matching_sites,
            reason: None,
            discovered_card: previous,
        });
    }
    Box::pin(discover_card(provider, client, matching_sites, previous)).await
}

/// Resolve a bearer credential and preserve the shared failure reasons.
async fn resolve_bearer_token(
    provider: &AgentToAgentProvider,
    client: &Client,
) -> Result<Result<Option<credentials::BearerToken>, String>, OperatorError> {
    let plan = match credentials::credential_plan_from_auth(provider.spec.auth.as_ref()) {
        Ok(plan) => plan,
        Err(_invalid_auth) => {
            let reason = credentials::credential_failure_reason_for_auth(provider.spec.auth.as_ref());
            return Ok(Err(reason.as_str().to_owned()));
        },
    };
    if let Some(reason) = credentials::verify_credential_accessible(client, &plan).await? {
        return Ok(Err(reason.as_str().to_owned()));
    }
    let CredentialPlan::Bearer(reference) = &plan else {
        return Ok(Ok(None));
    };
    let resolver = KubernetesSecretResolver::new(client.clone());
    let token = resolver
        .resolve(reference)
        .await
        .map_err(|_error| OperatorError::NotFound("credential became unavailable during resolution".to_owned()))?;
    Ok(Ok(Some(token)))
}

/// Run the live discovery probe after placement and credential validation.
async fn discover_card(
    provider: &AgentToAgentProvider,
    client: &Client,
    matching_sites: Vec<String>,
    previous: Option<AgentCardInfo>,
) -> Result<DesiredStatus, OperatorError> {
    if let Some(reason) = endpoint_tls::verify_tls_accessible(client, provider.spec.tls.as_ref()).await? {
        return Ok(unavailable(
            matching_sites,
            &reason.as_status_reason("Endpoint"),
            previous,
        ));
    }
    let token = match Box::pin(resolve_bearer_token(provider, client)).await? {
        Ok(token) => token,
        Err(reason) => return Ok(unavailable(matching_sites, &reason, previous)),
    };
    let outcome = Box::pin(run_card_probe(provider, client, token.as_ref())).await;
    let (phase, reason) = a2a_probe::phase_and_reason_from_probe(&outcome);
    let discovered_card = a2a_probe::discovered_card_after_probe(previous.as_ref(), &outcome);
    Ok(DesiredStatus {
        phase,
        matching_sites,
        reason,
        discovered_card,
    })
}

/// Run and measure one Agent Card discovery attempt.
async fn run_card_probe(
    provider: &AgentToAgentProvider,
    client: &Client,
    token: Option<&credentials::BearerToken>,
) -> a2a_probe::AgentCardProbeOutcome {
    let name = provider.metadata.name.as_deref().unwrap_or("unknown");
    let started = std::time::Instant::now();
    let outcome = Box::pin(a2a_probe::probe_agent_card(
        client,
        a2a_probe::AgentCardProbeRequest {
            endpoint: &provider.spec.endpoint,
            card_config: provider.spec.agent_card.as_ref(),
            tls_config: provider.spec.tls.as_ref(),
            provider_identity: name,
            auth_token: token,
            timeout: PROBE_TIMEOUT,
        },
    ))
    .await;
    crate::metrics::record_a2a_agent_card_probe(a2a_probe::probe_outcome_label(&outcome), started.elapsed());
    outcome
}

/// Build an unavailable desired status while retaining diagnostic card data.
fn unavailable(matching_sites: Vec<String>, reason: &str, discovered_card: Option<AgentCardInfo>) -> DesiredStatus {
    DesiredStatus {
        phase: ProviderPhase::Unavailable,
        matching_sites,
        reason: Some(reason.to_owned()),
        discovered_card,
    }
}

/// Patch status only when its complete semantic value changed.
async fn update_status(
    provider: &AgentToAgentProvider,
    client: &Client,
    desired: DesiredStatus,
    recorder: &Recorder,
    object_ref: &ObjectReference,
) -> Result<(), OperatorError> {
    let name = provider
        .metadata
        .name
        .as_deref()
        .unwrap_or_else(|| std::process::abort());
    let existing = provider.status.as_ref();
    let status = render_status(provider, desired);
    if !status_needs_update(existing, &status) {
        return Ok(());
    }
    let phase_changed = existing.map(|current| &current.phase) != Some(&status.phase);
    let reason_changed = existing.map(|current| &current.reason) != Some(&status.reason);
    Box::pin(apply_status_patch(client, name, &status)).await?;
    tracing::info!(name, "updated AgentToAgentProvider status");
    if phase_changed || reason_changed {
        emit_transition(
            name,
            existing.map(|current| &current.phase),
            &status,
            recorder,
            object_ref,
        )
        .await;
    }
    Ok(())
}

/// Apply one complete status document with server-side apply.
async fn apply_status_patch(
    client: &Client,
    name: &str,
    status: &AgentToAgentProviderStatus,
) -> Result<(), OperatorError> {
    let patch = serde_json::json!({
        "apiVersion": "grid.praxis.fast/v1alpha1",
        "kind": "AgentToAgentProvider",
        "status": status
    });
    Api::<AgentToAgentProvider>::all(client.clone())
        .patch_status(name, &PatchParams::apply(FIELD_MANAGER).force(), &Patch::Apply(patch))
        .await?;
    Ok(())
}

/// Render the complete status, including the current observed generation.
fn render_status(provider: &AgentToAgentProvider, desired: DesiredStatus) -> AgentToAgentProviderStatus {
    AgentToAgentProviderStatus {
        discovered_card: desired.discovered_card,
        matching_sites: desired.matching_sites,
        observed_generation: provider.metadata.generation.unwrap_or(0),
        phase: desired.phase,
        reason: desired.reason,
    }
}

/// Whether applying the desired status would make a semantic change.
fn status_needs_update(current: Option<&AgentToAgentProviderStatus>, desired: &AgentToAgentProviderStatus) -> bool {
    current != Some(desired)
}

/// Emit bounded transition telemetry after a successful status write.
async fn emit_transition(
    name: &str,
    previous_phase: Option<&ProviderPhase>,
    status: &AgentToAgentProviderStatus,
    recorder: &Recorder,
    object_ref: &ObjectReference,
) {
    let reason = telemetry_reason(&status.phase, status.reason.as_deref());
    let from = previous_phase.map_or("None", phase_label);
    let to = phase_label(&status.phase);
    tracing::info!(
        name,
        previous_phase = from,
        phase = to,
        reason,
        "AgentToAgentProvider phase transition"
    );
    let event = Event {
        type_: event_type(reason),
        reason: reason.to_owned(),
        note: status.reason.clone(),
        action: "Reconcile".to_owned(),
        secondary: None,
    };
    if let Err(error) = recorder.publish(&event, object_ref).await {
        tracing::warn!(%error, "failed to publish AgentToAgentProvider event");
    }
    crate::metrics::record_agent_to_agent_provider_phase_transition(from, to, reason);
}

/// Bounded provider phase label.
fn phase_label(phase: &ProviderPhase) -> &'static str {
    match phase {
        ProviderPhase::Pending => "Pending",
        ProviderPhase::Available => "Available",
        ProviderPhase::Degraded => "Degraded",
        ProviderPhase::Unavailable => "Unavailable",
    }
}

/// Stable reason used when a healthy status intentionally has no reason.
fn telemetry_reason<'reason>(phase: &ProviderPhase, reason: Option<&'reason str>) -> &'reason str {
    match reason {
        Some(reason) => reason,
        None if *phase == ProviderPhase::Available => "AgentCardDiscovered",
        None => "AwaitingSiteMatch",
    }
}

/// Healthy transition events are normal; every failure reason is warning.
fn event_type(reason: &str) -> EventType {
    match reason {
        "AgentCardDiscovered" | "AwaitingSiteMatch" => EventType::Normal,
        _ => EventType::Warning,
    }
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn valid_provider_configuration_accepts_origin_relative_discovery() {
        let provider = test_provider("https://agent.example/a2a", "network");
        assert!(
            validate_provider_config(&provider),
            "a valid endpoint and network reference must pass static validation"
        );
    }

    #[test]
    fn invalid_endpoint_or_blank_network_fails_before_kubernetes_work() {
        for (endpoint, network) in [
            ("http://localhost:8080/a2a", "network"),
            ("https://agent.example/a2a", " "),
            ("not-a-url", "network"),
        ] {
            let provider = test_provider(endpoint, network);
            assert!(
                !validate_provider_config(&provider),
                "invalid endpoint {endpoint:?} or network {network:?} must fail static validation"
            );
        }
    }

    #[test]
    fn selector_matches_all_labels_and_sorts_site_names() {
        let provider = provider_with_selector(&[("region", "east"), ("tier", "gpu")]);
        let sites = vec![
            site_with_labels("z-site", &[("region", "east"), ("tier", "gpu")]),
            site_with_labels("wrong-tier", &[("region", "east"), ("tier", "cpu")]),
            site_with_labels("a-site", &[("region", "east"), ("tier", "gpu"), ("extra", "ok")]),
        ];
        assert_eq!(
            sites_matching_selector(&provider, &sites),
            vec!["a-site", "z-site"],
            "selector matching must use AND semantics and deterministic ordering"
        );
    }

    #[test]
    fn empty_selector_matches_every_supplied_site() {
        let provider = provider_with_selector(&[]);
        let sites = vec![site_with_labels("b-site", &[]), site_with_labels("a-site", &[])];
        assert_eq!(
            sites_matching_selector(&provider, &sites),
            vec!["a-site", "b-site"],
            "an empty selector must match every site already filtered to the network"
        );
    }

    #[test]
    fn rendered_status_observes_current_generation_and_retained_card() {
        let mut provider = test_provider("https://agent.example/a2a", "network");
        provider.metadata.generation = Some(7);
        let card = sample_card();
        let status = render_status(
            &provider,
            DesiredStatus {
                phase: ProviderPhase::Unavailable,
                matching_sites: vec!["site-a".to_owned()],
                reason: Some("AgentCardUnreachable".to_owned()),
                discovered_card: Some(card.clone()),
            },
        );
        assert_eq!(
            status.observed_generation, 7,
            "every result must acknowledge the reconciled generation"
        );
        assert_eq!(
            status.discovered_card,
            Some(card),
            "an unavailable refresh may retain bounded card data for diagnostics"
        );
        assert_eq!(
            status.phase,
            ProviderPhase::Unavailable,
            "retained card data must not keep the provider available"
        );
    }

    #[test]
    fn identical_status_skips_patch_but_generation_change_requires_one() {
        let current = AgentToAgentProviderStatus {
            phase: ProviderPhase::Available,
            observed_generation: 3,
            ..AgentToAgentProviderStatus::default()
        };
        assert!(
            !status_needs_update(Some(&current), &current),
            "an identical semantic status must not cause an API patch"
        );
        let changed = AgentToAgentProviderStatus {
            observed_generation: 4,
            ..current.clone()
        };
        assert!(
            status_needs_update(Some(&current), &changed),
            "a new metadata generation must be acknowledged even when discovery data is unchanged"
        );
    }

    #[test]
    fn transition_telemetry_labels_and_event_types_are_bounded() {
        assert_eq!(
            telemetry_reason(&ProviderPhase::Available, None),
            "AgentCardDiscovered",
            "available without a reason must use the healthy bounded label"
        );
        assert_eq!(
            telemetry_reason(&ProviderPhase::Pending, None),
            "AwaitingSiteMatch",
            "pending without a reason must use the placement label"
        );
        assert_eq!(
            event_type("AgentCardDiscovered"),
            EventType::Normal,
            "healthy transitions must publish normal events"
        );
        assert_eq!(
            event_type("AgentCardInvalid"),
            EventType::Warning,
            "failure reasons must publish warning events"
        );
    }

    fn test_provider(endpoint: &str, network: &str) -> AgentToAgentProvider {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis.fast/v1alpha1",
            "kind": "AgentToAgentProvider",
            "metadata": {"name": "agent"},
            "spec": {"gridNetworkRef": network, "endpoint": endpoint}
        }))
        .unwrap()
    }

    fn provider_with_selector(labels: &[(&str, &str)]) -> AgentToAgentProvider {
        let match_labels: serde_json::Map<String, serde_json::Value> = labels
            .iter()
            .map(|(key, value)| ((*key).to_owned(), serde_json::Value::String((*value).to_owned())))
            .collect();
        serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis.fast/v1alpha1",
            "kind": "AgentToAgentProvider",
            "metadata": {"name": "agent"},
            "spec": {
                "gridNetworkRef": "network",
                "endpoint": "https://agent.example/a2a",
                "siteSelector": {"matchLabels": match_labels}
            }
        }))
        .unwrap()
    }

    fn site_with_labels(name: &str, labels: &[(&str, &str)]) -> GridSite {
        let labels: serde_json::Map<String, serde_json::Value> = labels
            .iter()
            .map(|(key, value)| ((*key).to_owned(), serde_json::Value::String((*value).to_owned())))
            .collect();
        serde_json::from_value(serde_json::json!({
            "apiVersion": "grid.praxis.fast/v1alpha1",
            "kind": "GridSite",
            "metadata": {"name": name, "labels": labels},
            "spec": {"gridNetworkRef": "network"}
        }))
        .unwrap()
    }

    fn sample_card() -> AgentCardInfo {
        AgentCardInfo {
            name: "Agent".to_owned(),
            version: Some("1".to_owned()),
            protocol_version: Some("1.0".to_owned()),
            default_input_modes: vec!["text/plain".to_owned()],
            default_output_modes: vec!["text/plain".to_owned()],
            interfaces: Vec::new(),
            streaming: false,
            skills: Vec::new(),
        }
    }
}
