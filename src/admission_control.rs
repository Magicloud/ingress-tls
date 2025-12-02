use std::{collections::BTreeMap, str::FromStr};

use eyre::eyre;
use json_patch::{AddOperation, Patch, PatchOperation, ReplaceOperation, jsonptr::PointerBuf};
use k8s_openapi::api::networking::v1::{Ingress, IngressSpec, IngressTLS};
use kube::{
    api::DynamicObject,
    core::admission::{AdmissionRequest, AdmissionResponse},
};
use logcall::logcall;
use tracing::instrument;

use crate::{
    cli::Cli,
    helpers::{
        Either, INGRESS_KIND, NGINX_FORCE_SSL_REDIRECT, SupportedIngressClass,
        TRAEFIK_MIDDLEWARE_ANNOTATION, dynamic_object2ingress, get_default_ingressclass,
    },
};

#[instrument]
#[logcall]
pub fn validate_ingress(request: &AdmissionRequest<DynamicObject>) -> AdmissionResponse {
    let mut ret = AdmissionResponse::from(request);

    if request.kind == *INGRESS_KIND.get().expect("INGRESS_KIND not initialized")
        && let Some(ref ingress_obj) = request.object
        && let Ok(ingress) = dynamic_object2ingress(ingress_obj.clone())
        && let Some(spec) = ingress.spec
        && let Some(tls) = spec.tls
        && !tls.is_empty()
    {
        // The ingress already has TLS defined.
        ret.allowed = true;
    } else {
        ret = ret.deny("There is no TLS defined in this Ingress");
    }

    ret
}

#[instrument]
#[logcall]
pub async fn mutate_ingress(
    request: &AdmissionRequest<DynamicObject>,
    conf: &Cli,
) -> AdmissionResponse {
    if request.kind == *INGRESS_KIND.get().expect("INGRESS_KIND not initialized")
        && let Some(ref ingress_obj) = request.object
        && let Ok(mut ingress) = dynamic_object2ingress(ingress_obj.clone())
        && let Some(spec) = ingress.spec.take()
    {
        if let Some(ref tls) = spec.tls
            && !tls.is_empty()
        {
            // The ingress already has TLS defined.
            let mut ret = AdmissionResponse::from(request);
            ret.allowed = true;
            ret
        } else {
            match if let Some(ref ic) = spec.ingress_class_name {
                Ok(ic.clone())
            } else {
                get_default_ingressclass()
                    .await
                    .and_then(|x| x.ok_or_else(|| eyre!("No default IngressClass found")))
            }
            .and_then(|ic| SupportedIngressClass::from_str(&ic))
            {
                Ok(ic) => actual_mutating(spec, request, ingress, conf, ic),
                Err(e) => {
                    let ret = AdmissionResponse::from(request);
                    ret.deny(format!("{e:?}"))
                }
            }
        }
    } else {
        // matched admission control rules, but not a valid Ingress?
        AdmissionResponse::invalid("Cannot get valid Ingress with spec")
    }
}

#[instrument]
#[logcall]
fn actual_mutating(
    spec: IngressSpec,
    request: &AdmissionRequest<DynamicObject>,
    ingress: Ingress,
    conf: &Cli,
    ingress_class: SupportedIngressClass,
) -> AdmissionResponse {
    // /spec/tls
    let mut tls_path = PointerBuf::root();
    tls_path.push_back("spec");
    tls_path.push_back("tls");

    let hosts = spec
        .rules
        .map(|rules| rules.into_iter().filter_map(|rule| rule.host).collect());
    let secret_name = if request.name.is_empty() {
        // the name could be empty in some cases the request relies on K8S to generate the name
        // TODO: random 7 chars
        "empty-name-ingress-tls".to_owned()
    } else {
        format!("{}-tls", request.name)
    };
    let tls = vec![IngressTLS {
        // If no hosts were specified in rules, leave the judgement to cert SAN.
        // But will cert-manager generate cert without host info?
        hosts,
        secret_name: Some(secret_name),
    }];
    let tls = serde_json::to_value(tls).map_err(|e| eyre!("{e:?}"));

    // /metadata/annotations
    let mut annotation_path = PointerBuf::root();
    annotation_path.push_back("metadata");
    annotation_path.push_back("annotations");
    let original_annotations = ingress.metadata.annotations.as_ref().map(|x| {
        x.iter()
            .map(|(k, v)| (Either::A(k), Either::A(v)))
            .collect::<BTreeMap<_, _>>()
    });
    let no_annotations = original_annotations.is_none();
    let mut annotations = original_annotations.unwrap_or_default();
    annotations.append(
        &mut conf
            .cert_manager_annotations
            .iter()
            .map(|(k, v)| (Either::A(k), Either::A(v)))
            .collect::<BTreeMap<_, _>>(),
    );
    let annotations = match ingress_class {
        SupportedIngressClass::Traefik => conf.traefik_ingress_redirect_resource_name.as_ref().map_or_else(
            || {
                Err(eyre!(
                    "Did not provide Traefik redirect middleware while the Ingress Class is Traefik"
                ))
            },
            |value| {
                let (ns, n) = if let Some((ns, n)) = value.split_once('/') {
                    (ns.to_owned(), n.to_owned())
                } else {
                    let ns = ingress.metadata.namespace.unwrap_or_else(||"default".to_owned());
                    (ns, value.clone())
                };
                let a = format!("{ns}-{n}@kubernetescrd");
                annotations
                    .entry(Either::B(TRAEFIK_MIDDLEWARE_ANNOTATION))
                    .and_modify(|v| *v = Either::B(format!("{v},{a}")))
                    .or_insert(Either::B(a));
                Ok(annotations)
            },
        ),
        SupportedIngressClass::Nginx => {
            annotations.insert(Either::B(NGINX_FORCE_SSL_REDIRECT), Either::B("true".to_owned()));
            Ok(annotations)
        }
    };
    let annotations = annotations
        .and_then(|annotations| serde_json::to_value(annotations).map_err(|e| eyre!("{e:?}")));

    // It is time like this that I wonder why try_blocks is still nightly
    match tls.and_then(|tls| {
        annotations.and_then(|annotations| {
            let ret = AdmissionResponse::from(request);
            ret.with_patch(Patch(vec![
                if no_annotations {
                    // Is there a better way to code this?
                    PatchOperation::Add(AddOperation {
                        path: annotation_path,
                        value: annotations,
                    })
                } else {
                    PatchOperation::Replace(ReplaceOperation {
                        path: annotation_path,
                        value: annotations,
                    })
                },
                PatchOperation::Replace(ReplaceOperation {
                    path: tls_path,
                    value: tls,
                }),
            ]))
            .map_err(|e| eyre!("{e:?}"))
        })
    }) {
        Ok(ret) => ret,
        Err(e) => AdmissionResponse::invalid(format!("Cannot generate patch for {e}")),
    }
}
