//! Shared outbound HTTP client construction for provider discovery probes.
//!
//! Every caller receives the same no-proxy, no-redirect, DNS-pinned client
//! and the same custom CA and mTLS handling. Protocol-specific modules remain
//! responsible for request and response semantics.

use crate::{
    crd::inference_provider::{ClientCertificateSecretRef, EndpointTlsConfig},
    resources::{
        endpoint_resolution::ResolvedEndpoint,
        endpoint_tls::{read_ca_for_tls, read_secret_bytes_for_tls, secret_ref_from_client_cert},
        tls_backend::{validate_pem_certificates, validate_pem_private_key},
    },
};

/// Stable status reason for an unusable client certificate and key pair.
pub(crate) const ENDPOINT_TLS_IDENTITY_MISMATCH: &str = "EndpointTlsIdentityMismatch";

/// Failure while constructing a provider discovery HTTP client.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum EndpointHttpClientError {
    /// The underlying HTTP client could not be constructed.
    Unreachable,
    /// Referenced TLS material was missing or invalid.
    TlsConfigInvalid(String),
}

/// Build a no-proxy, no-redirect, DNS-pinned HTTP client.
///
/// Custom CA and client identity material are attached only when `tls_config`
/// is present. Callers decide whether the target origin is authorized to
/// receive that identity before passing the configuration here.
pub(crate) async fn build_endpoint_client(
    kube_client: &kube::Client,
    tls_config: Option<&EndpointTlsConfig>,
    provider_identity: &str,
    resolved: &ResolvedEndpoint,
) -> Result<reqwest::Client, EndpointHttpClientError> {
    let mut builder = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());

    if let Some(hostname) = resolved.hostname() {
        builder = builder.resolve_to_addrs(hostname, resolved.addrs());
    }

    if let Some(tls) = tls_config {
        builder = attach_tls_material(builder, kube_client, tls, provider_identity).await?;
    }

    builder
        .build()
        .map_err(|_build_error| EndpointHttpClientError::Unreachable)
}

/// Attach the configured private CA and optional client identity.
pub(crate) async fn attach_tls_material(
    builder: reqwest::ClientBuilder,
    kube_client: &kube::Client,
    tls: &EndpointTlsConfig,
    provider_identity: &str,
) -> Result<reqwest::ClientBuilder, EndpointHttpClientError> {
    let builder = Box::pin(attach_tls_ca(builder, kube_client, tls, provider_identity)).await?;
    let Some(client_ref) = &tls.client_certificate_secret_ref else {
        return Ok(builder);
    };
    Box::pin(attach_tls_client_identity(
        builder,
        kube_client,
        client_ref,
        provider_identity,
    ))
    .await
}

/// Read one TLS value and retain the shared stable reason mapping.
pub(crate) async fn read_tls_material(
    kube_client: &kube::Client,
    secret_ref: &crate::crd::grid_network::SecretRef,
    key_name: &str,
    provider_identity: &str,
    material_desc: &str,
) -> Result<Vec<u8>, EndpointHttpClientError> {
    read_secret_bytes_for_tls(kube_client, secret_ref, key_name, provider_identity, material_desc)
        .await
        .map_err(|(reason, message)| {
            tracing::warn!(
                provider_identity,
                error = %message,
                material_desc,
                "provider probe TLS material invalid"
            );
            EndpointHttpClientError::TlsConfigInvalid(reason.as_status_reason("Endpoint"))
        })
}

/// Attach the configured private CA as the client's only trusted root set.
pub(crate) async fn attach_tls_ca(
    builder: reqwest::ClientBuilder,
    kube_client: &kube::Client,
    tls: &EndpointTlsConfig,
    provider_identity: &str,
) -> Result<reqwest::ClientBuilder, EndpointHttpClientError> {
    let ca_pem = Box::pin(read_ca_for_tls(kube_client, tls, provider_identity))
        .await
        .map_err(|(reason, message)| {
            tracing::warn!(provider_identity, error = %message, "provider probe TLS material invalid");
            EndpointHttpClientError::TlsConfigInvalid(reason.as_status_reason("Endpoint"))
        })?;
    if let Err(error) = validate_pem_certificates(&ca_pem) {
        tracing::warn!(provider_identity, error = %error, "provider probe CA PEM unparseable");
        return Err(EndpointHttpClientError::TlsConfigInvalid(
            "EndpointTlsMaterialInvalid".to_owned(),
        ));
    }
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).map_err(|error| {
        tracing::warn!(provider_identity, error = %error, "provider probe CA PEM unparseable");
        EndpointHttpClientError::TlsConfigInvalid("EndpointTlsMaterialInvalid".to_owned())
    })?;
    Ok(builder.tls_certs_only([ca_cert]))
}

/// Build a rustls client identity from one certificate and key PEM pair.
#[cfg(not(feature = "fips"))]
fn build_probe_client_identity(cert_pem: &[u8], key_pem: &[u8]) -> Result<reqwest::Identity, reqwest::Error> {
    let capacity = cert_pem.len().saturating_add(key_pem.len());
    let mut combined = Vec::with_capacity(capacity);
    combined.extend_from_slice(cert_pem);
    combined.extend_from_slice(key_pem);
    reqwest::Identity::from_pem(&combined)
}

/// Build an OpenSSL-backed client identity from one certificate and key PEM pair.
#[cfg(feature = "fips")]
fn build_probe_client_identity(cert_pem: &[u8], key_pem: &[u8]) -> Result<reqwest::Identity, reqwest::Error> {
    reqwest::Identity::from_pkcs8_pem(cert_pem, key_pem)
}

/// Attach a validated mTLS client certificate and private key.
#[expect(
    clippy::too_many_lines,
    reason = "sequential certificate and key reads followed by eager validation"
)]
pub(crate) async fn attach_tls_client_identity(
    builder: reqwest::ClientBuilder,
    kube_client: &kube::Client,
    client_ref: &ClientCertificateSecretRef,
    provider_identity: &str,
) -> Result<reqwest::ClientBuilder, EndpointHttpClientError> {
    let cert_ref = secret_ref_from_client_cert(client_ref);
    let identity_pem = Box::pin(read_tls_material(
        kube_client,
        &cert_ref,
        &client_ref.certificate_key,
        provider_identity,
        "client cert",
    ))
    .await?;
    let key_pem = Box::pin(read_tls_material(
        kube_client,
        &cert_ref,
        &client_ref.private_key_key,
        provider_identity,
        "client key",
    ))
    .await?;
    if let Err(error) = validate_pem_certificates(&identity_pem) {
        tracing::warn!(provider_identity, error = %error, "provider probe client certificate unparseable");
        return Err(EndpointHttpClientError::TlsConfigInvalid(
            ENDPOINT_TLS_IDENTITY_MISMATCH.to_owned(),
        ));
    }
    if let Err(error) = validate_pem_private_key(&key_pem) {
        tracing::warn!(provider_identity, error = %error, "provider probe client key unparseable");
        return Err(EndpointHttpClientError::TlsConfigInvalid(
            ENDPOINT_TLS_IDENTITY_MISMATCH.to_owned(),
        ));
    }
    let identity = build_probe_client_identity(&identity_pem, &key_pem).map_err(|error| {
        tracing::warn!(provider_identity, error = %error, "provider probe client identity unparseable");
        EndpointHttpClientError::TlsConfigInvalid(ENDPOINT_TLS_IDENTITY_MISMATCH.to_owned())
    })?;
    Ok(builder.identity(identity))
}
