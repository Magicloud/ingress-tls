use std::{collections::BTreeMap, str::FromStr};

use eyre::{Result, eyre};
use gateway_api::{
    gateways::{
        Gateway, GatewayListeners, GatewayListenersAllowedRoutesNamespaces,
        GatewayListenersAllowedRoutesNamespacesFrom, GatewayListenersTlsMode,
    },
    httproutes::{
        HTTPRoute, HTTPRouteParentRefs, HTTPRouteRulesFiltersRequestRedirectScheme,
        HTTPRouteRulesFiltersType,
    },
};
use json_patch::{AddOperation, Patch, PatchOperation, ReplaceOperation, jsonptr::PointerBuf};
use just_string::JustString;
use k8s_openapi::api::networking::v1::{Ingress, IngressSpec, IngressTLS};
use kube::core::admission::AdmissionResponse;
use tracing::instrument;

#[allow(clippy::wildcard_imports)]
use crate::{cli::Cli, helpers::*};

#[instrument]
pub fn validate_ingress(mut ret: AdmissionResponse, ingress: Ingress) -> AdmissionResponse {
    if let Some(spec) = ingress.spec
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

// This is not enough. One could have a full gateway but only http (non-redirect) route.
// Once we have Gateway ready. Validate HTTPRoute.
// httproute should be (parent)http -> redirect, (parent)https -> allow.
// http one must only be redirect. So if no https route, accessing fails.

// Based on this logic, how to mutate?
// Gateway: Add HTTPS protocol listener. Need hostname and port.
// If http listener is 80, assume https is 443, otherwise fails.
// When a non-redirect http route comes in, turn it into https section.
// If there is no redirect http route after all, not so bad.
#[instrument]
pub async fn validate_gateway(mut ret: AdmissionResponse, gateway: Gateway) -> AdmissionResponse {
    tracing::debug!("Working on HTTPRoutes attached to HTTP listener");
    let empty_string = String::new();
    let http_listeners = gateway
        .spec
        .listeners
        .iter()
        .filter(|l| l.protocol == "HTTP");
    let def_ns = DEFAULT_NAMESPACE
        .get()
        .expect("Cannot get DEFAULT_NAMESPACE");
    if let Some(ref gateway_name) = gateway.metadata.name {
        for (i, listener) in http_listeners.enumerate() {
            tracing::debug!("Working on listener {i}: {}", listener.name,);
            let httproutes = get_httproutes_for_listener(
                listener,
                gateway_name,
                gateway.metadata.namespace.as_ref().unwrap_or(def_ns),
            )
            .await;
            match httproutes {
                Ok(httproutes) => {
                    tracing::debug!(
                        "{} HTTPRoute-s are attached to this listener",
                        httproutes.len()
                    );
                    let (_good, bad): (Vec<HTTPRoute>, Vec<HTTPRoute>) =
                        httproutes.into_iter().partition(verify_httproute);
                    let bad = bad
                        .into_iter()
                        .map(|h| {
                            format!(
                                "{}/{}",
                                h.metadata.namespace.as_ref().unwrap_or(&empty_string),
                                h.metadata.name.as_ref().unwrap_or(&empty_string)
                            )
                        })
                        .collect::<Vec<_>>();
                    if !bad.is_empty() {
                        ret = ret.deny(format!(
                            "There are {} non-redirect HTTPRoutes ref this Gateway, which are {}",
                            bad.len(),
                            bad.join(", "),
                        ));
                        return ret;
                    }
                }
                Err(e) => {
                    tracing::error!("{e:?}");
                    ret = ret.deny("Internal Error");
                    return ret;
                }
            }
        }
    }

    tracing::debug!("Check if there is no HTTPS listener");
    if let Some(listener) = gateway
        .spec
        .listeners
        .iter()
        .find(|l| l.protocol == "HTTPS")
        // `HTTPS` without `tls` is invalid, won't be programmed.
        // Hence it is reasonable not checking the following.
        && let Some(ref tls) = listener.tls
        && (tls.mode == Some(GatewayListenersTlsMode::Passthrough)
            || (tls.mode == Some(GatewayListenersTlsMode::Terminate)
                && tls.certificate_refs.is_some()
                && !tls.certificate_refs.as_ref().unwrap().is_empty()))
    {
        // The gateway already has TLS defined.
        ret.allowed = true;
    } else {
        ret = ret.deny("There is no TLS defined in this Gateway");
    }

    ret
}

#[instrument]
pub async fn validate_httproute(
    mut ret: AdmissionResponse,
    httproute: HTTPRoute,
) -> AdmissionResponse {
    let empty_string = String::new();
    if let Some(ref parents) = httproute.spec.parent_refs {
        let def_ns = DEFAULT_NAMESPACE
            .get()
            .expect("Cannot get DEFAULT_NAMESPACE");
        let mut is_http = vec![];
        for (i, parent) in parents.iter().enumerate() {
            tracing::debug!(
                "Working on ParentRef {i}: {:?}/{}/{:?}",
                parent.namespace,
                parent.name,
                parent.section_name
            );
            // Some means the route is for http(s) listener.
            // None means other kinds, we do not care.
            if parent.kind == Some("Gateway".to_owned()) {
                match get_gateway(parent.namespace.as_ref().unwrap_or(def_ns), &parent.name).await {
                    Err(e) => {
                        tracing::error!("{e:?}");
                        ret = ret.deny("Internal Error");
                        return ret;
                    }
                    Ok(None) => {
                        // The parent-refed Gateway does not exist yet
                        // Move on
                    }
                    Ok(Some(gateway)) => {
                        tracing::debug!("Found gateway");
                        let listener = gateway.spec.listeners.into_iter().find(|listener| {
                            does_parentref_listener_equal(
                                parent,
                                listener,
                                gateway.metadata.name.as_ref().unwrap_or(&empty_string),
                                gateway.metadata.namespace.as_ref().unwrap_or(def_ns),
                                httproute.metadata.namespace.as_ref().unwrap_or(def_ns),
                            )
                        });
                        if let Some(listener) = listener {
                            tracing::debug!("Found listener of {}", listener.protocol);
                            if listener.protocol == "HTTP" {
                                is_http.push(format!(
                                    "{}/{}",
                                    gateway.metadata.namespace.as_ref().unwrap_or(&empty_string),
                                    gateway.metadata.name.as_ref().unwrap_or(&empty_string)
                                ));
                            }
                        }
                    }
                }
            }
        }
        if is_http.is_empty() {
            // this HTTPRoute is purely for HTTPS listener
            ret.allowed = true;
        } else {
            // this HTTPRoute serves HTTP listener
            if verify_httproute(&httproute) {
                ret.allowed = true;
            } else {
                ret = ret.deny(format!("This HTTPRoute is not redirect, yet it works for non-HTTPS listeners in Gateways: {}", is_http.join(", ")));
            }
        }
    } else {
        // Not for anything yet
        ret.allowed = true;
    }
    ret
}

#[instrument]
fn verify_httproute(httproute: &HTTPRoute) -> bool {
    if let Some(ref rules) = httproute.spec.rules
        && rules.len() == 1
        && let Some(rule) = rules.first()
        && rule.backend_refs.is_none()
        && let Some(ref filters) = rule.filters
        && filters.len() == 1
        && let Some(filter) = filters.first()
        && filter.r#type == HTTPRouteRulesFiltersType::RequestRedirect
        && let Some(ref rr) = filter.request_redirect
        && rr.scheme == Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https)
    {
        // HTTP route with only redirect
        true
    } else if httproute.spec.rules.is_none() || httproute.spec.rules == Some(Vec::new()) {
        // Not for anything yet
        true
    } else {
        tracing::warn!("{}", serde_yaml::to_string(httproute).unwrap());
        false
    }
}

#[instrument]
async fn get_httproutes_for_listener(
    listener: &GatewayListeners,
    gateway_name: &str,
    gateway_namespace: &str,
) -> Result<Vec<HTTPRoute>> {
    let def_ns = DEFAULT_NAMESPACE
        .get()
        .expect("Cannot get DEFAULT_NAMESPACE");
    if let Some(ref ar) = listener.allowed_routes {
        let ns_sel = ar
            .namespaces
            .as_ref()
            .unwrap_or(&GatewayListenersAllowedRoutesNamespaces {
                from: Some(GatewayListenersAllowedRoutesNamespacesFrom::Same),
                selector: None,
            });
        // convert to `Namespaces`
        let namespaces = match ns_sel.from {
            Some(GatewayListenersAllowedRoutesNamespacesFrom::All) => Namespaces::All,
            Some(GatewayListenersAllowedRoutesNamespacesFrom::Selector) => {
                let m = ns_sel
                    .selector
                    .as_ref()
                    .and_then(|sel| sel.match_expressions.clone())
                    .map(|exps| {
                        exps.into_iter()
                            .map(std::convert::TryInto::try_into)
                            .collect::<Result<Vec<SelectorByLabel>>>()
                    })
                    .transpose()?
                    .unwrap_or_default();
                let mut l = ns_sel
                    .selector
                    .as_ref()
                    .and_then(|sel| sel.match_labels.clone())
                    .map(|lbls| {
                        lbls.into_iter()
                            .map(std::convert::Into::into)
                            .collect::<Vec<SelectorByLabel>>()
                    })
                    .unwrap_or_default();
                let mut selectors = m;
                selectors.append(&mut l);
                let nss = filter_namespaces(&selectors).await?;
                Namespaces::Some(nss.into_iter().map(JustString::String).collect())
            }
            Some(GatewayListenersAllowedRoutesNamespacesFrom::Same) | None => {
                Namespaces::Some(vec![JustString::RefStr(gateway_namespace)])
            }
        };
        tracing::debug!("{namespaces:?}");
        // Get HTTPRoutes that parentRef to this Gateway
        let httproutes = get_httproutes(&namespaces).await?;
        tracing::debug!("Totally {} HTTPRoutes found", httproutes.len());
        let x: Vec<HTTPRoute> = httproutes
            .into_iter()
            .filter(|httproute| {
                let hns = httproute.metadata.namespace.as_ref().unwrap_or(def_ns);
                if let Some(ref parentrefs) = httproute.spec.parent_refs
                    && parentrefs.iter().all(|parentref| {
                        does_parentref_listener_equal(
                            parentref,
                            listener,
                            gateway_name,
                            gateway_namespace,
                            hns,
                        )
                    })
                {
                    true
                } else {
                    false
                }
            })
            .collect();
        tracing::debug!("{} HTTPRoutes found for the listener", x.len());
        Ok(x)
    } else {
        Ok(vec![])
    }
}

fn does_parentref_listener_equal(
    p: &HTTPRouteParentRefs,
    l: &GatewayListeners,
    gn: &str,
    gns: &str,
    hns: &str,
) -> bool {
    let hns = hns.to_string();
    p.kind == Some("Gateway".to_string())
        && p.name == gn
        && p.namespace.as_ref().unwrap_or(&hns) == gns
        && p.section_name.as_ref().is_none_or(|psn| psn == &l.name)
        && p.port.is_none_or(|pp| pp == l.port)
}

#[instrument]
pub fn mutate_ingress(
    mut ret: AdmissionResponse,
    mut ingress: Ingress,
    conf: &Cli,
) -> AdmissionResponse {
    if let Some(spec) = ingress.spec.take() {
        if let Some(ref tls) = spec.tls
            && !tls.is_empty()
        {
            // The ingress already has TLS defined.
            ret.allowed = true;
            ret
        } else {
            // DefaultIngressClass webhook runs first.
            // Hence here, we should always get `spec.ingressClassName`.
            match spec
                .ingress_class_name
                .as_ref()
                .ok_or_else(|| eyre!("spec.ingressClassName should be there"))
                .and_then(|ic| SupportedIngressClass::from_str(ic))
            {
                Ok(ic) => actual_mutating(ret, spec, ingress, conf, ic),
                Err(e) => ret.deny(format!("{e:?}")),
            }
        }
    } else {
        // matched admission control rules, but not a valid Ingress?
        AdmissionResponse::invalid("Cannot get valid Ingress with spec")
    }
}

#[instrument]
fn actual_mutating(
    ret: AdmissionResponse,
    spec: IngressSpec,
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
    if hosts.is_none() {
        // If no hosts were specified in rules, leave the judgement to cert SAN.
        // But cert-manager rejects
        return ret.deny("No hosts given");
    }
    let secret_name = if let Some(name) = ingress.metadata.name
        && !name.is_empty()
    {
        format!("{name}-tls")
    } else {
        // the name could be empty in some cases the request relies on K8S to generate the name
        // TODO: random 7 chars
        "empty-name-ingress-tls".to_owned()
    };
    let tls = vec![IngressTLS {
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
            .map(|(k, v)| (JustString::RefString(k), JustString::RefString(v)))
            .collect::<BTreeMap<_, _>>()
    });
    let no_annotations = original_annotations.is_none();
    let mut annotations = original_annotations.unwrap_or_default();

    if let Some(ref x) = conf.cma {
        if let Some(ref group) = x.group {
            annotations.insert(ISSUER_GROUP, JustString::RefString(group));
        }
        if let Some(ref kind) = x.kind {
            annotations.insert(ISSUER_KIND, JustString::RefString(kind));
        }
        match x.issuer {
            Issuer::Namespaced(ref i) => {
                annotations.insert(ISSUER, JustString::RefString(i));
            }
            Issuer::Clustered(ref i) => {
                annotations.insert(CLUSTER_ISSUER, JustString::RefString(i));
            }
        }
    }

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
                    .entry(TRAEFIK_MIDDLEWARE_ANNOTATION)
                    .and_modify(|v| *v = JustString::String(format!("{v},{a}")))
                    .or_insert(JustString::String(a));
                Ok(annotations)
            },
        ),
        SupportedIngressClass::Nginx => {
            annotations.insert(NGINX_FORCE_SSL_REDIRECT, JustString::RefStr("true"));
            Ok(annotations)
        }
    };
    let annotations = annotations
        .and_then(|annotations| serde_json::to_value(annotations).map_err(|e| eyre!("{e:?}")));

    // It is time like this that I wonder why try_blocks is still nightly
    match tls.and_then(|tls| {
        annotations.and_then(|annotations| {
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

#[instrument]
pub fn mutate_gateway(
    mut ret: AdmissionResponse,
    mut gateway: Gateway,
    conf: &Cli,
) -> AdmissionResponse {
    if let Some(listener) = gateway
        .spec
        .listeners
        .iter()
        .find(|l| l.protocol == "HTTPS")
        && let Some(ref tls) = listener.tls
        && (tls.mode == Some(GatewayListenersTlsMode::Passthrough)
            || (tls.mode == Some(GatewayListenersTlsMode::Terminate)
                && tls.certificate_refs.is_some()
                && !tls.certificate_refs.as_ref().unwrap().is_empty()))
    {
        // The gateway already has TLS defined.
        ret.allowed = true;
    } else {
        ret = ret.deny("There is no TLS defined in this Ingress");
        // adding HTTPS section with tls and cert-manager annotations
        // is not enough.
    }

    ret
}
