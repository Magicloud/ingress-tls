use std::{collections::BTreeMap, str::FromStr};

use eyre::Result;
use itertools::Itertools;
use k8s_openapi::api::networking::v1::{Ingress, IngressTLS};
use tracing::instrument;

#[allow(clippy::wildcard_imports)]
use crate::{cli::Cli, helpers::*};

#[instrument]
pub fn validate_ingress(ingress: &Ingress) -> Result<Status> {
    let has_tls = || {
        if ingress.spec.as_ref()?.tls.as_ref()?.is_empty() {
            Some(Ok(Status::MoveOn))
        } else {
            Some(Ok(Status::Denied(DenyReason::IngressNoTLS)))
        }
    };
    let skip = || {
        let skip = ingress
            .metadata
            .annotations
            .as_ref()?
            .get(SKIP_ANNOTATION)?;
        if skip == "true" {
            Some(Ok(Status::Allowed))
        } else {
            Some(Ok(Status::MoveOn))
        }
    };

    let checks: Vec<Box<dyn Fn() -> Option<Result<Status>>>> =
        vec![Box::new(skip), Box::new(has_tls)];
    let mut accum = Ok(Status::MoveOn);
    for check in checks {
        if matches!(accum, Ok(Status::MoveOn)) {
            match check() {
                Some(s) => accum = s,
                None => {
                    accum = Ok(Status::Invalid(
                        "The input does not contain enough information".to_string(),
                    ));
                }
            }
        } else {
            break;
        }
    }
    accum
}

#[instrument]
pub fn mutate_ingress(ingress: &Ingress, conf: &Cli) -> Result<Status> {
    mutate_ingress_(ingress, conf).unwrap_or_else(|| {
        Ok(Status::Invalid(
            "The input does not contain enough information".to_string(),
        ))
    })
}

#[instrument]
fn patch_annotations(
    annotations: &mut BTreeMap<String, String>,
    ic: &Result<SupportedIngressClass>,
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
    if let Ok(ic) = ic {
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
    } else {
        tracing::warn!("{ic:?}");
    }
}

#[instrument]
fn mutate_ingress_(ingress: &Ingress, conf: &Cli) -> Option<Result<Status>> {
    let validate_result = validate_ingress(ingress);
    if matches!(
        validate_result,
        Ok(Status::Denied(DenyReason::IngressNoTLS))
    ) {
        let name = ingress.metadata.name.as_ref()?;
        let ns = ingress.metadata.namespace.as_ref()?;
        let ic =
            SupportedIngressClass::from_str(ingress.spec.as_ref()?.ingress_class_name.as_ref()?);
        let mut hosts = ingress
            .spec
            .as_ref()?
            .rules
            .as_ref()?
            .iter()
            .filter_map(|x| x.host.clone())
            .collect::<Vec<_>>();
        if let Some(edns) = get_external_dns_hostname(ingress) {
            hosts.extend(edns.into_iter());
        }
        let hosts = hosts.into_iter().unique().collect::<Vec<_>>();
        let ret = if hosts.is_empty() {
            Status::Invalid("The Ingress does not contain hosts information".to_string())
        } else {
            let tls = vec![IngressTLS {
                hosts: Some(hosts),
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
        };
        Some(Ok(ret))
    } else {
        Some(validate_result)
    }
}
