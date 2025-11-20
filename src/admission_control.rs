use std::collections::BTreeMap;

use eyre::eyre;
use json_patch::{AddOperation, Patch, PatchOperation, ReplaceOperation, jsonptr::PointerBuf};
use k8s_openapi::api::networking::v1::{Ingress, IngressSpec, IngressTLS};
use kube::{
    api::DynamicObject,
    core::admission::{AdmissionRequest, AdmissionResponse},
};
use logcall::logcall;
use smol::lock::OnceCell;
use tracing::instrument;

use crate::{
    cli::Cli,
    helpers::{Either, INGRESS_KIND, dynamic_object2ingress},
};

pub static TRAEFIK_MIDDLEWARE_ANNOTATION: OnceCell<String> = OnceCell::new();

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
pub fn mutate_ingress(request: &AdmissionRequest<DynamicObject>, conf: &Cli) -> AdmissionResponse {
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
            actual_mutating(spec, request, ingress, conf)
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
            .map(|(k, v)| (k, Either::A(v)))
            .collect::<BTreeMap<_, _>>()
    });
    let no_annotations = original_annotations.is_none();
    let mut annotations = original_annotations.unwrap_or_default();
    annotations.append(
        &mut conf
            .cert_manager_annotations
            .iter()
            .map(|(k, v)| (k, Either::A(v)))
            .collect::<BTreeMap<_, _>>(),
    );
    annotations
        .entry(
            TRAEFIK_MIDDLEWARE_ANNOTATION
                .get()
                .expect("TRAEFIK_MIDDLEWARE_ANNOTATION is not initialized"),
        )
        .and_modify(|v| *v = Either::B(format!("{v},{}", conf.ingress_redirect_resource_name)))
        .or_insert(Either::A(&conf.ingress_redirect_resource_name));
    let annotations = serde_json::to_value(annotations).map_err(|e| eyre!("{e:?}"));

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
