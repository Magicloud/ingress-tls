use std::{collections::BTreeMap, str::FromStr};

use eyre::Result;
use itertools::Itertools;
use k8s_openapi::api::networking::v1::{Ingress, IngressTLS};
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
pub fn mutate_ingress(ingress: &Ingress, conf: &Cli) -> Status {
    match validate_ingress(ingress) {
        Status::Allowed => Status::Allowed,
        Status::Denied(deny_reason) => match deny_reason {
            DenyReason::InternalError(ref _r) => Status::Denied(deny_reason),
            DenyReason::IngressNoTLS => {
                let edns_hostname = get_external_dns_hostname(ingress);
                if let Some(ref name) = ingress.metadata.name
                    && let Some(ref spec) = ingress.spec
                    && let Some(ref icn) = spec.ingress_class_name
                    && let icn = SupportedIngressClass::from_str(icn)
                    && let Ok(ic) = icn
                    && let Some(ref rules) = spec.rules
                    && let hosts = rules
                        .iter()
                        .map(|x| x.host.as_ref())
                        .collect::<Vec<_>>()
                        .push_return(edns_hostname.as_ref())
                        .into_iter()
                        .flatten()
                        .unique()
                        .collect::<Vec<_>>()
                    && !hosts.is_empty()
                {
                    let ns = ingress.metadata.namespace.as_ref().unwrap_or_else(|| {
                        DEFAULT_NAMESPACE
                            .get()
                            .expect("DEFAULT_NAMESPACE not initialized")
                    });
                    let tls = vec![IngressTLS {
                        hosts: Some(hosts.into_iter().cloned().collect()),
                        secret_name: Some(format!("{name}-tls")),
                    }];
                    let mut target = ingress.clone();
                    let mut annotations = target.metadata.annotations.take().unwrap_or_default();
                    if let Some(s) = target.spec.as_mut() {
                        s.tls = Some(tls);
                    }
                    patch_annotations(&mut annotations, &ic, ns, conf);
                    target.metadata.annotations = Some(annotations);

                    match patch(ingress, &target) {
                        Ok(p) => Status::Patch(p),
                        Err(e) => Status::Denied(DenyReason::InternalError(e)),
                    }
                } else {
                    Status::Invalid("The Ingress does not contain enough information".to_string())
                }
            }
            _ => unimplemented!(),
        },
        _ => unimplemented!(),
    }
}

#[instrument]
fn patch_annotations(
    annotations: &mut BTreeMap<String, String>,
    ic: &SupportedIngressClass,
    ns: &str,
    conf: &Cli,
) {
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
    match ic {
        SupportedIngressClass::Traefik => {
            if let Some(ref value) = conf.traefik_ingress_redirect_resource_name {
                let (ns, n) = value.split_once('/').unwrap_or((ns, value));
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
}
