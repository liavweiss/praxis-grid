//! Bounded A2A v1 Agent Card discovery.
//!
//! Discovery is a side-effect-free HTTP GET. The configured provider
//! endpoint remains authoritative: card interface URLs are validated against
//! its origin and are never adopted as routing destinations.

use std::{collections::BTreeSet, time::Duration};

use futures::StreamExt as _;
use serde::Deserialize;

use crate::{
    crd::{
        agent_to_agent_provider::{
            AgentCardConfig, AgentCardInfo, AgentInterfaceInfo, AgentSkillInfo, AgentToAgentBinding,
            DEFAULT_AGENT_CARD_PATH, MAX_INTERFACES, MAX_MODE_COUNT, MAX_MODE_LENGTH, MAX_SKILL_ID_LENGTH,
            MAX_SKILL_NAME_LENGTH, MAX_SKILLS, MAX_VERSION_LENGTH,
        },
        inference_provider::{EndpointTlsConfig, ProviderPhase},
    },
    resources::{
        credentials::BearerToken,
        endpoint_http_client::{self, EndpointHttpClientError},
        endpoint_resolution::{self, EndpointUrlValidation},
    },
};

/// Maximum Agent Card response body accepted by discovery.
const MAX_AGENT_CARD_BYTES: usize = 512 * 1024;

/// Result of one Agent Card discovery attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AgentCardProbeOutcome {
    /// A valid, routable, bounded card was discovered.
    Success(Box<AgentCardInfo>),
    /// DNS, connection, TLS handshake, or the outer timeout failed.
    Unreachable,
    /// The endpoint returned malformed, oversized, or non-success content.
    InvalidResponse,
    /// No A2A v1 JSON-RPC interface was advertised.
    UnsupportedBinding,
    /// A supported interface used a different origin than `spec.endpoint`.
    EndpointMismatch,
    /// No valid skill remained after applying the configured allowlist.
    NoRoutableSkills,
    /// The server rejected discovery credentials with HTTP 401 or 403.
    AuthRejected,
    /// A bearer token could not be encoded safely as an HTTP header.
    AuthConfigInvalid,
    /// Referenced endpoint TLS material was missing or invalid.
    TlsConfigInvalid(String),
}

/// Parameters for one bounded Agent Card discovery attempt.
pub(crate) struct AgentCardProbeRequest<'request> {
    /// Operator-configured final A2A endpoint.
    pub(crate) endpoint: &'request str,
    /// Optional Agent Card discovery override and skill allowlist.
    pub(crate) card_config: Option<&'request AgentCardConfig>,
    /// Optional custom trust and client identity for same-origin HTTPS.
    pub(crate) tls_config: Option<&'request EndpointTlsConfig>,
    /// Provider name used only for safe log attribution.
    pub(crate) provider_identity: &'request str,
    /// Resolved bearer token for same-origin HTTPS discovery.
    pub(crate) auth_token: Option<&'request BearerToken>,
    /// Total wall-clock budget for resolution, Secret reads, and HTTP I/O.
    pub(crate) timeout: Duration,
}

/// Map a discovery outcome to provider phase and stable status reason.
pub(crate) fn phase_and_reason_from_probe(outcome: &AgentCardProbeOutcome) -> (ProviderPhase, Option<String>) {
    let reason = match outcome {
        AgentCardProbeOutcome::Success(_) => return (ProviderPhase::Available, None),
        AgentCardProbeOutcome::Unreachable => "AgentCardUnreachable",
        AgentCardProbeOutcome::InvalidResponse => "AgentCardInvalid",
        AgentCardProbeOutcome::UnsupportedBinding => "AgentCardUnsupportedBinding",
        AgentCardProbeOutcome::EndpointMismatch => "AgentCardEndpointMismatch",
        AgentCardProbeOutcome::NoRoutableSkills => "AgentCardNoRoutableSkills",
        AgentCardProbeOutcome::AuthRejected => "A2aAuthRejected",
        AgentCardProbeOutcome::AuthConfigInvalid => "A2aAuthTokenInvalid",
        AgentCardProbeOutcome::TlsConfigInvalid(reason) => {
            return (ProviderPhase::Unavailable, Some(reason.clone()));
        },
    };
    (ProviderPhase::Unavailable, Some(reason.to_owned()))
}

/// Return the bounded label used by probe telemetry.
pub(crate) fn probe_outcome_label(outcome: &AgentCardProbeOutcome) -> &'static str {
    match outcome {
        AgentCardProbeOutcome::Success(_) => "Success",
        AgentCardProbeOutcome::Unreachable => "Unreachable",
        AgentCardProbeOutcome::InvalidResponse => "InvalidResponse",
        AgentCardProbeOutcome::UnsupportedBinding => "UnsupportedBinding",
        AgentCardProbeOutcome::EndpointMismatch => "EndpointMismatch",
        AgentCardProbeOutcome::NoRoutableSkills => "NoRoutableSkills",
        AgentCardProbeOutcome::AuthRejected => "AuthRejected",
        AgentCardProbeOutcome::AuthConfigInvalid => "AuthConfigInvalid",
        AgentCardProbeOutcome::TlsConfigInvalid(_) => "TlsConfigInvalid",
    }
}

/// Preserve the last discovered card after a failed refresh.
pub(crate) fn discovered_card_after_probe(
    previous: Option<&AgentCardInfo>,
    outcome: &AgentCardProbeOutcome,
) -> Option<AgentCardInfo> {
    match outcome {
        AgentCardProbeOutcome::Success(card) => Some(card.as_ref().clone()),
        AgentCardProbeOutcome::Unreachable
        | AgentCardProbeOutcome::InvalidResponse
        | AgentCardProbeOutcome::UnsupportedBinding
        | AgentCardProbeOutcome::EndpointMismatch
        | AgentCardProbeOutcome::NoRoutableSkills
        | AgentCardProbeOutcome::AuthRejected
        | AgentCardProbeOutcome::AuthConfigInvalid
        | AgentCardProbeOutcome::TlsConfigInvalid(_) => previous.cloned(),
    }
}

/// Validate discovery URL/path configuration without Kubernetes or network I/O.
pub(crate) fn validate_discovery_config(endpoint: &str, card_config: Option<&AgentCardConfig>) -> bool {
    discovery_target(endpoint, card_config).is_ok()
}

/// Discover and validate one A2A Agent Card within one outer timeout.
pub(crate) async fn probe_agent_card(
    kube_client: &kube::Client,
    request: AgentCardProbeRequest<'_>,
) -> AgentCardProbeOutcome {
    match tokio::time::timeout(request.timeout, probe_agent_card_unbounded(kube_client, request)).await {
        Ok(outcome) => outcome,
        Err(_elapsed) => AgentCardProbeOutcome::Unreachable,
    }
}

/// Discovery sequence wrapped by [`probe_agent_card`]'s outer timeout.
async fn probe_agent_card_unbounded(
    kube_client: &kube::Client,
    request: AgentCardProbeRequest<'_>,
) -> AgentCardProbeOutcome {
    let target = match discovery_target(request.endpoint, request.card_config) {
        Ok(target) => target,
        Err(outcome) => return outcome,
    };
    let resolved = match endpoint_resolution::resolve_endpoint(&target.uri, request.timeout).await {
        Ok(resolved) => resolved,
        Err(_resolution_error) => return AgentCardProbeOutcome::Unreachable,
    };
    let tls_config = target.send_sensitive.then_some(request.tls_config).flatten();
    let client = match endpoint_http_client::build_endpoint_client(
        kube_client,
        tls_config,
        request.provider_identity,
        &resolved,
    )
    .await
    {
        Ok(client) => client,
        Err(error) => return map_client_error(error),
    };
    let token = target.send_sensitive.then_some(request.auth_token).flatten();
    let bytes = match fetch_card(&client, &target.url, token).await {
        Ok(bytes) => bytes,
        Err(outcome) => return outcome,
    };
    parse_agent_card(&bytes, &target.endpoint_origin, request.card_config)
}

/// Translate shared client construction failures to A2A outcomes.
fn map_client_error(error: EndpointHttpClientError) -> AgentCardProbeOutcome {
    match error {
        EndpointHttpClientError::Unreachable => AgentCardProbeOutcome::Unreachable,
        EndpointHttpClientError::TlsConfigInvalid(reason) => AgentCardProbeOutcome::TlsConfigInvalid(reason),
    }
}

/// Origin used for credential scoping and card-interface authority checks.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Origin {
    /// Lowercase URL scheme.
    scheme: String,
    /// Lowercase hostname without IPv6 brackets.
    host: String,
    /// Explicit or scheme-default port.
    port: u16,
}

impl Origin {
    /// Parse the origin of an absolute HTTP(S) URI.
    fn from_uri(uri: &http::Uri) -> Result<Self, AgentCardProbeOutcome> {
        let scheme = uri.scheme_str().ok_or(AgentCardProbeOutcome::InvalidResponse)?;
        let host = uri.host().ok_or(AgentCardProbeOutcome::InvalidResponse)?;
        let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
        Ok(Self {
            scheme: scheme.to_ascii_lowercase(),
            host: host.trim_matches(['[', ']']).to_ascii_lowercase(),
            port,
        })
    }
}

/// Validated discovery target and credential-scope decision.
struct DiscoveryTarget {
    /// Full discovery URL.
    url: String,
    /// Parsed discovery URI.
    uri: http::Uri,
    /// Configured provider endpoint origin.
    endpoint_origin: Origin,
    /// Whether auth and custom TLS identity may be used for this target.
    send_sensitive: bool,
}

/// Resolve the explicit or well-known card location against endpoint origin.
fn discovery_target(
    endpoint: &str,
    card_config: Option<&AgentCardConfig>,
) -> Result<DiscoveryTarget, AgentCardProbeOutcome> {
    let endpoint_uri = validated_uri(endpoint)?;
    let endpoint_origin = Origin::from_uri(&endpoint_uri)?;
    if card_config.is_some_and(|config| config.url.is_some() && config.path.is_some()) {
        return Err(AgentCardProbeOutcome::InvalidResponse);
    }
    let url = if let Some(url) = card_config.and_then(|config| config.url.as_deref()) {
        url.to_owned()
    } else {
        let path = card_config
            .and_then(|config| config.path.as_deref())
            .unwrap_or(DEFAULT_AGENT_CARD_PATH);
        if !valid_origin_path(path) {
            return Err(AgentCardProbeOutcome::InvalidResponse);
        }
        let scheme = endpoint_uri
            .scheme_str()
            .ok_or(AgentCardProbeOutcome::InvalidResponse)?;
        let authority = endpoint_uri.authority().ok_or(AgentCardProbeOutcome::InvalidResponse)?;
        format!("{scheme}://{authority}{path}")
    };
    let uri = validated_uri(&url)?;
    let card_origin = Origin::from_uri(&uri)?;
    let send_sensitive = card_origin == endpoint_origin && endpoint_origin.scheme == "https";
    Ok(DiscoveryTarget {
        url,
        uri,
        endpoint_origin,
        send_sensitive,
    })
}

/// Parse and apply the shared outbound endpoint validation policy.
fn validated_uri(value: &str) -> Result<http::Uri, AgentCardProbeOutcome> {
    if endpoint_resolution::validate_endpoint_url(value) != EndpointUrlValidation::Ok {
        return Err(AgentCardProbeOutcome::InvalidResponse);
    }
    value
        .parse()
        .map_err(|_parse_error| AgentCardProbeOutcome::InvalidResponse)
}

/// Whether a card path is an origin-relative path rather than an authority.
fn valid_origin_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains(['\\', '?', '#'])
        && !path.chars().any(char::is_whitespace)
}

/// Fetch one bounded card body without following redirects.
async fn fetch_card(
    client: &reqwest::Client,
    url: &str,
    auth_token: Option<&BearerToken>,
) -> Result<Vec<u8>, AgentCardProbeOutcome> {
    let mut request = client.get(url).header(http::header::ACCEPT, "application/json");
    if let Some(token) = auth_token {
        let value = token
            .authorization_header()
            .map_err(|_invalid_header| AgentCardProbeOutcome::AuthConfigInvalid)?;
        request = request.header(http::header::AUTHORIZATION, value);
    }
    let response = request
        .send()
        .await
        .map_err(|_request_error| AgentCardProbeOutcome::Unreachable)?;
    match response.status() {
        http::StatusCode::UNAUTHORIZED | http::StatusCode::FORBIDDEN => {
            return Err(AgentCardProbeOutcome::AuthRejected);
        },
        status if !status.is_success() => return Err(AgentCardProbeOutcome::InvalidResponse),
        _ => {},
    }
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(MAX_AGENT_CARD_BYTES).unwrap_or(u64::MAX))
    {
        return Err(AgentCardProbeOutcome::InvalidResponse);
    }
    bounded_body(response).await
}

/// Collect a streaming HTTP body while enforcing the response-size limit.
async fn bounded_body(response: reqwest::Response) -> Result<Vec<u8>, AgentCardProbeOutcome> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_body_error| AgentCardProbeOutcome::InvalidResponse)?;
        if body.len().saturating_add(chunk.len()) > MAX_AGENT_CARD_BYTES {
            return Err(AgentCardProbeOutcome::InvalidResponse);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Wire representation of the A2A v1 Agent Card fields discovery consumes.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAgentCard {
    /// Human-readable agent name.
    name: String,
    /// Required A2A description, validated but not persisted.
    description: String,
    /// Preferred and fallback protocol interfaces.
    supported_interfaces: Vec<RawAgentInterface>,
    /// Agent implementation version.
    version: String,
    /// Feature capability flags.
    capabilities: RawAgentCapabilities,
    /// Required card-level input modes.
    default_input_modes: Vec<String>,
    /// Required card-level output modes.
    default_output_modes: Vec<String>,
    /// Skills advertised by the agent.
    skills: Vec<RawAgentSkill>,
}

/// A2A Agent Card capabilities used by Grid.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAgentCapabilities {
    /// Whether streaming messages are supported.
    #[serde(default)]
    streaming: bool,
}

/// One A2A v1 supported interface.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAgentInterface {
    /// Interface URL, used only for origin validation.
    url: String,
    /// A2A protocol binding wire name.
    protocol_binding: String,
    /// A2A protocol version.
    protocol_version: String,
}

/// One raw Agent Card skill.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAgentSkill {
    /// Stable skill identifier.
    id: String,
    /// Human-readable skill name.
    name: String,
    /// Required skill description, validated but not persisted.
    description: String,
    /// Required routing tags, validated but not persisted.
    tags: Vec<String>,
    /// Optional card-default override.
    input_modes: Option<Vec<String>>,
    /// Optional card-default override.
    output_modes: Option<Vec<String>>,
}

/// Protocol-specific validation failure after JSON decoding.
enum CardValidationError {
    /// Required fields or configured bounds were invalid.
    Invalid,
    /// No supported A2A v1 JSON-RPC interface existed.
    UnsupportedBinding,
    /// Supported interfaces existed only on another origin.
    EndpointMismatch,
    /// No skill remained after the allowlist was applied.
    NoRoutableSkills,
}

/// Classification of one valid Agent Card interface.
enum InterfaceDisposition {
    /// Same-origin A2A v1 JSON-RPC interface retained in status.
    Supported(AgentInterfaceInfo),
    /// A2A v1 JSON-RPC interface on another origin.
    OtherOrigin,
    /// Valid interface using another binding or protocol major version.
    Unsupported,
}

/// Decode and reduce an A2A v1 card into the bounded status subset.
fn parse_agent_card(
    bytes: &[u8],
    endpoint_origin: &Origin,
    card_config: Option<&AgentCardConfig>,
) -> AgentCardProbeOutcome {
    let raw: RawAgentCard = match serde_json::from_slice(bytes) {
        Ok(raw) => raw,
        Err(_parse_error) => return AgentCardProbeOutcome::InvalidResponse,
    };
    match normalize_agent_card(raw, endpoint_origin, card_config) {
        Ok(card) => AgentCardProbeOutcome::Success(Box::new(card)),
        Err(CardValidationError::Invalid) => AgentCardProbeOutcome::InvalidResponse,
        Err(CardValidationError::UnsupportedBinding) => AgentCardProbeOutcome::UnsupportedBinding,
        Err(CardValidationError::EndpointMismatch) => AgentCardProbeOutcome::EndpointMismatch,
        Err(CardValidationError::NoRoutableSkills) => AgentCardProbeOutcome::NoRoutableSkills,
    }
}

/// Validate all routing-relevant fields and build bounded status data.
fn normalize_agent_card(
    raw: RawAgentCard,
    endpoint_origin: &Origin,
    card_config: Option<&AgentCardConfig>,
) -> Result<AgentCardInfo, CardValidationError> {
    validate_text(&raw.name, MAX_SKILL_NAME_LENGTH)?;
    validate_text(&raw.description, MAX_AGENT_CARD_BYTES)?;
    validate_text(&raw.version, MAX_VERSION_LENGTH)?;
    let default_input_modes = normalize_modes(raw.default_input_modes, true)?;
    let default_output_modes = normalize_modes(raw.default_output_modes, true)?;
    let (interfaces, protocol_version) = normalize_interfaces(raw.supported_interfaces, endpoint_origin)?;
    let allowlist = normalize_allowlist(card_config)?;
    let skills = normalize_skills(raw.skills, &default_input_modes, &default_output_modes, &allowlist)?;
    Ok(AgentCardInfo {
        name: raw.name,
        version: Some(raw.version),
        protocol_version: Some(protocol_version),
        default_input_modes,
        default_output_modes,
        interfaces,
        streaming: raw.capabilities.streaming,
        skills,
    })
}

/// Validate supported interfaces and retain same-origin JSON-RPC v1 entries.
fn normalize_interfaces(
    raw: Vec<RawAgentInterface>,
    endpoint_origin: &Origin,
) -> Result<(Vec<AgentInterfaceInfo>, String), CardValidationError> {
    if raw.is_empty() || raw.len() > MAX_INTERFACES {
        return Err(CardValidationError::Invalid);
    }
    let mut supported = Vec::new();
    let mut supported_other_origin = false;
    for interface in raw {
        match classify_interface(interface, endpoint_origin)? {
            InterfaceDisposition::Supported(interface) => supported.push(interface),
            InterfaceDisposition::OtherOrigin => supported_other_origin = true,
            InterfaceDisposition::Unsupported => {},
        }
    }
    if supported.is_empty() {
        return Err(if supported_other_origin {
            CardValidationError::EndpointMismatch
        } else {
            CardValidationError::UnsupportedBinding
        });
    }
    let mut interfaces = Vec::new();
    for interface in supported {
        if !interfaces.contains(&interface) {
            interfaces.push(interface);
        }
    }
    let protocol_version = interfaces
        .first()
        .and_then(|interface| interface.protocol_version.clone())
        .ok_or(CardValidationError::UnsupportedBinding)?;
    Ok((interfaces, protocol_version))
}

/// Validate and classify one advertised interface.
fn classify_interface(
    interface: RawAgentInterface,
    endpoint_origin: &Origin,
) -> Result<InterfaceDisposition, CardValidationError> {
    validate_text(&interface.protocol_binding, MAX_VERSION_LENGTH)?;
    validate_text(&interface.protocol_version, MAX_VERSION_LENGTH)?;
    let uri = validated_uri(&interface.url).map_err(|_outcome| CardValidationError::Invalid)?;
    let origin = Origin::from_uri(&uri).map_err(|_outcome| CardValidationError::Invalid)?;
    if interface.protocol_binding != "JSONRPC" || !protocol_is_v1(&interface.protocol_version) {
        return Ok(InterfaceDisposition::Unsupported);
    }
    if &origin != endpoint_origin {
        return Ok(InterfaceDisposition::OtherOrigin);
    }
    Ok(InterfaceDisposition::Supported(AgentInterfaceInfo {
        binding: AgentToAgentBinding::JsonRpc,
        protocol_version: Some(interface.protocol_version),
    }))
}

/// Whether a protocol version belongs to A2A major version 1.
fn protocol_is_v1(version: &str) -> bool {
    version.split('.').next() == Some("1")
}

/// Validate and normalize the optional skill allowlist.
fn normalize_allowlist(card_config: Option<&AgentCardConfig>) -> Result<BTreeSet<String>, CardValidationError> {
    let mut allowlist = BTreeSet::new();
    for skill_id in card_config
        .map(|config| config.skill_allowlist.as_slice())
        .unwrap_or_default()
    {
        validate_text(skill_id, MAX_SKILL_ID_LENGTH)?;
        if !allowlist.insert(skill_id.clone()) {
            return Err(CardValidationError::Invalid);
        }
    }
    Ok(allowlist)
}

/// Validate skills, apply defaults and the allowlist, and sort by ID.
fn normalize_skills(
    raw: Vec<RawAgentSkill>,
    default_input_modes: &[String],
    default_output_modes: &[String],
    allowlist: &BTreeSet<String>,
) -> Result<Vec<AgentSkillInfo>, CardValidationError> {
    if raw.is_empty() || raw.len() > MAX_SKILLS {
        return Err(CardValidationError::Invalid);
    }
    let mut ids = BTreeSet::new();
    let mut skills = Vec::new();
    for skill in raw {
        validate_text(&skill.id, MAX_SKILL_ID_LENGTH)?;
        validate_text(&skill.name, MAX_SKILL_NAME_LENGTH)?;
        validate_text(&skill.description, MAX_AGENT_CARD_BYTES)?;
        validate_tags(&skill.tags)?;
        if !ids.insert(skill.id.clone()) {
            return Err(CardValidationError::Invalid);
        }
        let input_modes = effective_modes(skill.input_modes, default_input_modes)?;
        let output_modes = effective_modes(skill.output_modes, default_output_modes)?;
        if allowlist.is_empty() || allowlist.contains(&skill.id) {
            skills.push(AgentSkillInfo {
                id: skill.id,
                name: skill.name,
                input_modes,
                output_modes,
            });
        }
    }
    if skills.is_empty() {
        return Err(CardValidationError::NoRoutableSkills);
    }
    skills.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(skills)
}

/// Validate non-empty required tags without persisting them in status.
fn validate_tags(tags: &[String]) -> Result<(), CardValidationError> {
    if tags.is_empty() || tags.iter().any(|tag| tag.trim().is_empty()) {
        return Err(CardValidationError::Invalid);
    }
    Ok(())
}

/// Use a non-empty skill override, otherwise inherit the card defaults.
fn effective_modes(modes: Option<Vec<String>>, defaults: &[String]) -> Result<Vec<String>, CardValidationError> {
    match modes {
        Some(modes) if !modes.is_empty() => normalize_modes(modes, true),
        Some(_) | None => Ok(defaults.to_vec()),
    }
}

/// Validate, sort, and deduplicate MIME mode strings.
fn normalize_modes(mut modes: Vec<String>, require_nonempty: bool) -> Result<Vec<String>, CardValidationError> {
    if modes.len() > MAX_MODE_COUNT || (require_nonempty && modes.is_empty()) {
        return Err(CardValidationError::Invalid);
    }
    if modes.iter().any(|mode| {
        mode.is_empty() || mode.len() > MAX_MODE_LENGTH || !mode.bytes().all(|byte| (b'!'..=b'~').contains(&byte))
    }) {
        return Err(CardValidationError::Invalid);
    }
    modes.sort();
    modes.dedup();
    Ok(modes)
}

/// Validate a required bounded text field by Unicode scalar count.
fn validate_text(value: &str, max_chars: usize) -> Result<(), CardValidationError> {
    if value.trim().is_empty() || value.chars().count() > max_chars {
        return Err(CardValidationError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::sync::Arc;

    use axum::{Router, body::Body, extract::Request, http::Response, routing::get};
    use serde_json::Value;

    use super::*;

    #[test]
    fn valid_v1_card_produces_bounded_status_and_effective_modes() {
        let outcome = parse_fixture(&valid_card(), None);
        let AgentCardProbeOutcome::Success(card) = outcome else {
            std::process::abort();
        };
        assert_eq!(card.name, "Claims Agent", "card name must be retained");
        assert_eq!(
            card.protocol_version.as_deref(),
            Some("1.0"),
            "preferred v1 protocol must be selected"
        );
        assert!(card.streaming, "streaming capability must be retained");
        assert_eq!(card.skills.len(), 2, "both valid skills must be retained");
        assert_eq!(
            card.skills[0].input_modes,
            vec!["text/plain"],
            "a missing skill inputModes override must inherit card defaults"
        );
        assert_eq!(
            card.skills[1].output_modes,
            vec!["application/pdf"],
            "a skill outputModes override must replace card defaults"
        );
    }

    #[test]
    fn skill_allowlist_uses_ids_and_filters_deterministically() {
        let config = card_config(&["review"]);
        let outcome = parse_fixture(&valid_card(), Some(&config));
        let AgentCardProbeOutcome::Success(card) = outcome else {
            std::process::abort();
        };
        assert_eq!(card.skills.len(), 1, "only the allowed skill ID must remain");
        assert_eq!(card.skills[0].id, "review", "allowlist must compare stable skill IDs");
    }

    #[test]
    fn unknown_allowlist_ids_yield_no_routable_skills() {
        let config = card_config(&["unknown"]);
        assert_eq!(
            parse_fixture(&valid_card(), Some(&config)),
            AgentCardProbeOutcome::NoRoutableSkills,
            "an allowlist with no discovered IDs must fail closed"
        );
    }

    #[test]
    fn duplicate_skill_ids_are_invalid() {
        let mut card = valid_card();
        card["skills"][1]["id"] = Value::String("claims".to_owned());
        assert_eq!(
            parse_fixture(&card, None),
            AgentCardProbeOutcome::InvalidResponse,
            "duplicate skill identity is ambiguous and must be rejected"
        );
    }

    #[test]
    fn blank_and_oversized_skill_catalogs_are_invalid() {
        let mut blank = valid_card();
        blank["skills"][0]["id"] = Value::String(" ".to_owned());
        assert_eq!(
            parse_fixture(&blank, None),
            AgentCardProbeOutcome::InvalidResponse,
            "blank skill IDs must not enter routing state"
        );

        let skill = valid_card()["skills"][0].clone();
        let mut oversized = valid_card();
        oversized["skills"] = Value::Array(vec![skill; MAX_SKILLS.saturating_add(1)]);
        assert_eq!(
            parse_fixture(&oversized, None),
            AgentCardProbeOutcome::InvalidResponse,
            "skill count must respect the published status bound"
        );
    }

    #[test]
    fn malformed_or_incomplete_json_is_invalid() {
        let origin = Origin {
            scheme: "https".to_owned(),
            host: "agent.example".to_owned(),
            port: 443,
        };
        assert_eq!(
            parse_agent_card(b"{", &origin, None),
            AgentCardProbeOutcome::InvalidResponse,
            "malformed JSON must be rejected"
        );
        assert_eq!(
            parse_agent_card(br#"{"name":"incomplete"}"#, &origin, None),
            AgentCardProbeOutcome::InvalidResponse,
            "missing required A2A v1 fields must be rejected"
        );
    }

    #[test]
    fn oversized_or_non_ascii_modes_are_invalid() {
        let mut oversized = valid_card();
        oversized["defaultInputModes"] =
            serde_json::to_value(vec!["x"; MAX_MODE_COUNT.saturating_add(1)]).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            parse_fixture(&oversized, None),
            AgentCardProbeOutcome::InvalidResponse,
            "mode count must respect the published status bound"
        );

        let mut non_ascii = valid_card();
        non_ascii["defaultInputModes"] = serde_json::json!(["text/π"]);
        assert_eq!(
            parse_fixture(&non_ascii, None),
            AgentCardProbeOutcome::InvalidResponse,
            "status modes must stay in the published visible-ASCII alphabet"
        );
    }

    #[test]
    fn unsupported_or_old_protocol_binding_is_rejected() {
        let mut grpc = valid_card();
        grpc["supportedInterfaces"][0]["protocolBinding"] = Value::String("GRPC".to_owned());
        assert_eq!(
            parse_fixture(&grpc, None),
            AgentCardProbeOutcome::UnsupportedBinding,
            "v1 currently supports only JSONRPC"
        );

        let mut old = valid_card();
        old["supportedInterfaces"][0]["protocolVersion"] = Value::String("0.3.0".to_owned());
        assert_eq!(
            parse_fixture(&old, None),
            AgentCardProbeOutcome::UnsupportedBinding,
            "pre-v1 JSON-RPC cards must not enter v1 routing state"
        );
    }

    #[test]
    fn supported_interface_on_different_origin_is_a_mismatch() {
        let mut card = valid_card();
        card["supportedInterfaces"][0]["url"] = Value::String("https://other.example/a2a".to_owned());
        assert_eq!(
            parse_fixture(&card, None),
            AgentCardProbeOutcome::EndpointMismatch,
            "a card must never replace the configured data-plane authority"
        );
    }

    #[test]
    fn preferred_interface_order_is_preserved() {
        let mut card = valid_card();
        card["supportedInterfaces"] = serde_json::json!([
            {"url": "https://agent.example/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.2"},
            {"url": "https://agent.example/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ]);
        let outcome = parse_fixture(&card, None);
        let AgentCardProbeOutcome::Success(discovered) = outcome else {
            std::process::abort();
        };
        assert_eq!(
            discovered.protocol_version.as_deref(),
            Some("1.2"),
            "the first supported interface is the card's preferred interface"
        );
    }

    #[test]
    fn default_and_custom_paths_resolve_against_endpoint_origin() {
        let default = discovery_target("https://agent.example/a2a/v1", None).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            default.url, "https://agent.example/.well-known/agent-card.json",
            "default discovery path must replace rather than append to endpoint path"
        );
        let config = AgentCardConfig {
            url: None,
            path: Some("/cards/public.json".to_owned()),
            skill_allowlist: Vec::new(),
        };
        let custom =
            discovery_target("https://agent.example/a2a/v1", Some(&config)).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            custom.url, "https://agent.example/cards/public.json",
            "custom path must resolve against the endpoint origin"
        );
    }

    #[test]
    fn credentials_are_scoped_to_same_origin_https() {
        let same = discovery_target("https://agent.example/a2a", None).unwrap_or_else(|_| std::process::abort());
        assert!(
            same.send_sensitive,
            "same-origin HTTPS discovery may receive auth and mTLS identity"
        );

        let cross_config = AgentCardConfig {
            url: Some("https://cards.example/agent.json".to_owned()),
            path: None,
            skill_allowlist: Vec::new(),
        };
        let cross = discovery_target("https://agent.example/a2a", Some(&cross_config))
            .unwrap_or_else(|_| std::process::abort());
        assert!(
            !cross.send_sensitive,
            "cross-origin discovery must not receive credentials"
        );

        let cleartext = discovery_target("http://agent.example/a2a", None).unwrap_or_else(|_| std::process::abort());
        assert!(!cleartext.send_sensitive, "HTTP discovery must not receive credentials");
    }

    #[test]
    fn authority_form_and_backslash_paths_are_rejected() {
        for path in ["//cards.example/x", "/\\cards.example/x"] {
            let config = AgentCardConfig {
                url: None,
                path: Some(path.to_owned()),
                skill_allowlist: Vec::new(),
            };
            assert!(
                !validate_discovery_config("https://agent.example/a2a", Some(&config)),
                "path {path:?} must not escape the configured endpoint origin"
            );
        }
    }

    #[test]
    fn failed_refresh_retains_previous_card_but_reports_failure() {
        let previous = sample_info();
        let outcome = AgentCardProbeOutcome::Unreachable;
        assert_eq!(
            discovered_card_after_probe(Some(&previous), &outcome),
            Some(previous),
            "a failed refresh must retain the last bounded card for diagnostics"
        );
        assert_eq!(
            phase_and_reason_from_probe(&outcome),
            (ProviderPhase::Unavailable, Some("AgentCardUnreachable".to_owned())),
            "retained data must not leave the provider routable"
        );
    }

    #[tokio::test]
    async fn fetch_sends_valid_bearer_authentication() {
        let auth = TestServer::spawn(|request| {
            let authorized = request
                .headers()
                .get(http::header::AUTHORIZATION)
                .is_some_and(|value| value == "Bearer token");
            if authorized {
                Response::builder().status(200).body(Body::from("{}")).unwrap()
            } else {
                Response::builder().status(401).body(Body::empty()).unwrap()
            }
        })
        .await;
        let token = BearerToken::new("token".to_owned());
        assert!(
            fetch_card(&no_redirect_client(), &auth.url, Some(&token)).await.is_ok(),
            "a valid bearer token must be attached to same-origin discovery"
        );
        assert_eq!(
            fetch_card(&no_redirect_client(), &auth.url, None).await,
            Err(AgentCardProbeOutcome::AuthRejected),
            "HTTP 401 must map to the stable authentication failure"
        );
    }

    #[tokio::test]
    async fn fetch_rejects_redirects() {
        let redirect = TestServer::spawn(|_request| {
            Response::builder()
                .status(302)
                .header(http::header::LOCATION, "https://other.example/card")
                .body(Body::empty())
                .unwrap()
        })
        .await;
        assert_eq!(
            fetch_card(&no_redirect_client(), &redirect.url, None).await,
            Err(AgentCardProbeOutcome::InvalidResponse),
            "redirects must be rejected rather than followed"
        );
    }

    #[tokio::test]
    async fn fetch_rejects_oversized_response_body() {
        let body = Arc::new(vec![b'x'; MAX_AGENT_CARD_BYTES + 1]);
        let oversized = TestServer::spawn(move |_request| {
            Response::builder()
                .status(200)
                .body(Body::from(Arc::clone(&body).as_ref().clone()))
                .unwrap()
        })
        .await;
        assert_eq!(
            fetch_card(&no_redirect_client(), &oversized.url, None).await,
            Err(AgentCardProbeOutcome::InvalidResponse),
            "an oversized card body must be rejected before JSON parsing"
        );
    }

    #[tokio::test]
    async fn invalid_bearer_header_fails_closed_before_request() {
        let token = BearerToken::new("bad\nvalue".to_owned());
        assert_eq!(
            fetch_card(&no_redirect_client(), "http://example.invalid/card", Some(&token)).await,
            Err(AgentCardProbeOutcome::AuthConfigInvalid),
            "an invalid bearer header must not fall back to anonymous discovery"
        );
    }

    #[tokio::test]
    async fn zero_outer_timeout_returns_unreachable_without_network_io() {
        let client = unused_kube_client();
        let outcome = probe_agent_card(
            &client,
            AgentCardProbeRequest {
                endpoint: "http://192.0.2.1/a2a",
                card_config: None,
                tls_config: None,
                provider_identity: "agent",
                auth_token: None,
                timeout: Duration::ZERO,
            },
        )
        .await;
        assert_eq!(
            outcome,
            AgentCardProbeOutcome::Unreachable,
            "one outer deadline must bound every discovery phase"
        );
    }

    fn parse_fixture(card: &Value, config: Option<&AgentCardConfig>) -> AgentCardProbeOutcome {
        let bytes = serde_json::to_vec(card).unwrap_or_else(|_| std::process::abort());
        parse_agent_card(
            &bytes,
            &Origin {
                scheme: "https".to_owned(),
                host: "agent.example".to_owned(),
                port: 443,
            },
            config,
        )
    }

    fn valid_card() -> Value {
        serde_json::json!({
            "name": "Claims Agent",
            "description": "Processes and reviews claims",
            "supportedInterfaces": [{
                "url": "https://agent.example/a2a",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0"
            }],
            "version": "2.3.0",
            "capabilities": {"streaming": true},
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["application/json"],
            "skills": [
                {
                    "id": "claims",
                    "name": "Claims Processing",
                    "description": "Process a claim",
                    "tags": ["claims"]
                },
                {
                    "id": "review",
                    "name": "Document Review",
                    "description": "Review a document",
                    "tags": ["documents"],
                    "inputModes": [],
                    "outputModes": ["application/pdf"]
                }
            ]
        })
    }

    fn card_config(ids: &[&str]) -> AgentCardConfig {
        AgentCardConfig {
            url: None,
            path: None,
            skill_allowlist: ids.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    fn sample_info() -> AgentCardInfo {
        AgentCardInfo {
            name: "Claims Agent".to_owned(),
            version: Some("1".to_owned()),
            protocol_version: Some("1.0".to_owned()),
            default_input_modes: vec!["text/plain".to_owned()],
            default_output_modes: vec!["text/plain".to_owned()],
            interfaces: vec![AgentInterfaceInfo {
                binding: AgentToAgentBinding::JsonRpc,
                protocol_version: Some("1.0".to_owned()),
            }],
            streaming: false,
            skills: vec![AgentSkillInfo {
                id: "claims".to_owned(),
                name: "Claims".to_owned(),
                input_modes: vec!["text/plain".to_owned()],
                output_modes: vec!["text/plain".to_owned()],
            }],
        }
    }

    fn no_redirect_client() -> reqwest::Client {
        #[cfg(not(feature = "fips"))]
        drop(rustls::crypto::ring::default_provider().install_default());
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    fn unused_kube_client() -> kube::Client {
        let service = tower::service_fn(|_request: http::Request<kube::client::Body>| async {
            Ok::<_, std::convert::Infallible>(Response::new(kube::client::Body::empty()))
        });
        kube::Client::new(service, "default")
    }

    struct TestServer {
        url: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl TestServer {
        async fn spawn(handler: impl Fn(Request) -> Response<Body> + Clone + Send + Sync + 'static) -> Self {
            let app = Router::new().route(
                "/",
                get(move |request: Request| {
                    let handler = handler.clone();
                    async move { handler(request) }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                url: format!("http://{address}/"),
                task,
            }
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
}
