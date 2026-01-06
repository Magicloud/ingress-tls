use std::str::FromStr;

use eyre::Result;
use just_string::JustString;
use k8s_openapi::api::networking::v1::{Ingress, IngressTLS};
use kube::core::admission::AdmissionResponse;
use tracing::instrument;

#[allow(clippy::wildcard_imports)]
use crate::{cli::Cli, helpers::*};

#[instrument]
pub fn validate_ingress(ingress: &Ingress) -> Status {
    let has_tls = || {
        if let Some(spec) = ingress.spec.as_ref()
            && let Some(tls) = spec.tls.as_ref()
            && !tls.is_empty()
        {
            Ok(Status::MoveOn)
        } else {
            Ok(Status::Denied(DenyReason::IngressNoTLS))
        }
    };
    let skip = || {
        if ingress
            .metadata
            .annotations
            .as_ref()
            .and_then(|a_s| a_s.get(SKIP_VALIDATE_ANNOTATION))
            .is_some_and(|v| v == "true")
        {
            Ok(Status::Allowed)
        } else {
            Ok(Status::MoveOn)
        }
    };

    let checks: Vec<Box<dyn Fn() -> Result<Status>>> = vec![Box::new(skip), Box::new(has_tls)];
    checks
        .into_iter()
        .try_fold(Status::MoveOn, |b, f| match b {
            Status::MoveOn => match f() {
                Ok(x) => Ok(x),
                Err(e) => Err(Status::Denied(DenyReason::InternalError(e))),
            },
            x => Err(x),
        })
        .extract()
}

#[instrument]
pub fn mutate_ingress(
    mut ret: AdmissionResponse,
    ingress: &Ingress,
    conf: &Cli,
) -> AdmissionResponse {
    if ingress
        .metadata
        .annotations
        .as_ref()
        .and_then(|a_s| a_s.get(&SKIP_MUTATE_ANNOTATION.to_string()))
        .is_some_and(|v| v == "true")
    {
        // TODO: Record the skipping event?
        ret.allowed = true;
        return ret;
    }
    if let Some(ref _name) = ingress.metadata.name
        && let Some(ref spec) = ingress.spec
        && let Some(ref _icn) = spec.ingress_class_name
        && let Some(ref rules) = spec.rules
        && !rules.is_empty()
    {
        // Is this a good idea? Precheck necessary data here, following steps
        // could just unwrap.
    } else {
        return AdmissionResponse::invalid("The Ingress does not contain enough information");
    }

    if ingress
        .spec
        .unwrap_ref()
        .tls
        .as_ref()
        .is_none_or(std::vec::Vec::is_empty)
    {
        // DefaultIngressClass webhook runs first.
        // Hence here, we should always get `spec.ingressClassName`.
        match actual_mutating_ingress(ret.clone(), ingress, conf) {
            Ok(r) => ret = r,
            Err(e) => {
                ret = ret.deny(format!("{e:?}"));
            }
        }
    } else {
        // The ingress already has TLS defined.
        ret.allowed = true;
    }
    ret
}

// Add cert manager annotation
// Add redirect annotation
// Add TLS field
#[instrument]
fn actual_mutating_ingress(
    ret: AdmissionResponse,
    ingress: &Ingress,
    conf: &Cli,
) -> Result<AdmissionResponse> {
    let mut target = ingress.clone();

    let hosts: Vec<String> = ingress
        .spec
        .unwrap_ref()
        .rules
        .unwrap_ref()
        .iter()
        .filter_map(|rule| rule.host.clone())
        .collect();
    if hosts.is_empty() {
        // If no hosts were specified in rules, leave the judgement to cert SAN.
        // But cert-manager rejects
        return Ok(AdmissionResponse::invalid("No hosts given"));
    }
    // the name could be empty in some cases the request relies on K8S to generate the name
    let secret_name = format!("{}-tls", ingress.metadata.name.unwrap_ref());
    let tls = vec![IngressTLS {
        hosts: Some(hosts),
        secret_name: Some(secret_name),
    }];
    if let Some(spec) = target.spec.as_mut() {
        spec.tls = Some(tls);
    }

    let mut annotations = target.metadata.annotations.take().unwrap_or_default();
    if let Some(ref x) = conf.cma {
        if let Some(ref group) = x.group {
            annotations
                .entry(ISSUER_GROUP.to_string())
                .or_insert_with(|| group.clone());
        }
        if let Some(ref kind) = x.kind {
            annotations
                .entry(ISSUER_KIND.to_string())
                .or_insert_with(|| kind.clone());
        }
        match x.issuer {
            Issuer::Namespaced(ref i) => {
                annotations
                    .entry(ISSUER.to_string())
                    .or_insert_with(|| i.clone());
            }
            Issuer::Clustered(ref i) => {
                annotations
                    .entry(CLUSTER_ISSUER.to_string())
                    .or_insert_with(|| i.clone());
            }
        }
    }
    let ingress_class =
        SupportedIngressClass::from_str(ingress.spec.unwrap_ref().ingress_class_name.unwrap_ref())?;
    match ingress_class {
        SupportedIngressClass::Traefik => {
            if let Some(ref value) = conf.traefik_ingress_redirect_resource_name {
                let (ns, n) = if let Some((ns, n)) = value.split_once('/') {
                    (JustString::RefStr(ns), JustString::RefStr(n))
                } else {
                    // I wonder if this will ever happens
                    let ns = ingress.metadata.namespace.as_ref().unwrap_or_else(|| {
                        DEFAULT_NAMESPACE
                            .get()
                            .expect("DEFAULT_NAMESPACE not initialized")
                    });
                    (JustString::RefString(ns), JustString::RefString(value))
                };
                let a = format!("{ns}-{n}@kubernetescrd");
                annotations
                    .entry(TRAEFIK_MIDDLEWARE_ANNOTATION.to_string())
                    .or_insert(a);
            }
        }
        SupportedIngressClass::Nginx => {
            annotations
                .entry(NGINX_FORCE_SSL_REDIRECT.to_string())
                .or_insert_with(|| "true".to_string());
        }
    }
    target.metadata.annotations = Some(annotations);

    patch(ingress, &target, ret)
}
