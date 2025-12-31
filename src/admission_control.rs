use std::str::FromStr;

use eyre::Result;
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
use just_string::JustString;
use k8s_openapi::api::networking::v1::{Ingress, IngressTLS};
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
    } else if ingress
        .metadata
        .annotations
        .as_ref()
        .and_then(|a_s| a_s.get(SKIP_VALIDATE_ANNOTATION))
        .is_some_and(|v| v == "true")
    {
        // TODO: Record the skipping event?
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
// If a httproute is refing the HTTP listener, there is nothing we can do, deny.
// If http listener is 80, assume https is 443, otherwise fails.
// When a non-redirect http route comes in, turn it into https section.
// If there is no redirect http route after all, not so bad.
#[instrument]
pub async fn validate_gateway(mut ret: AdmissionResponse, gateway: Gateway) -> AdmissionResponse {
    if gateway
        .metadata
        .annotations
        .as_ref()
        .and_then(|a_s| a_s.get(SKIP_VALIDATE_ANNOTATION))
        .is_some_and(|v| v == "true")
    {
        // TODO: Record the skipping event?
        ret.allowed = true;
        return ret;
    }

    match get_bad_httproute_for_gateway(&gateway).await {
        Ok(bad) => {
            let empty_string = String::new();
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
async fn get_bad_httproute_for_gateway(gateway: &Gateway) -> Result<Vec<HTTPRoute>> {
    let http_listeners = gateway
        .spec
        .listeners
        .iter()
        .filter(|l| l.protocol == "HTTP");
    let def_ns = DEFAULT_NAMESPACE
        .get()
        .expect("Cannot get DEFAULT_NAMESPACE");
    if let Some(ref gateway_name) = gateway.metadata.name {
        let mut ret = Vec::new();
        for (i, listener) in http_listeners.enumerate() {
            tracing::debug!("Working on listener {i}: {}", listener.name,);
            let httproutes = get_httproutes_for_listener(
                listener,
                gateway_name,
                gateway.metadata.namespace.as_ref().unwrap_or(def_ns),
            )
            .await?;
            tracing::debug!(
                "{} HTTPRoute-s are attached to this listener",
                httproutes.len()
            );
            let (_good, mut bad): (Vec<HTTPRoute>, Vec<HTTPRoute>) =
                httproutes.into_iter().partition(verify_httproute);
            ret.append(&mut bad);
        }
        Ok(ret)
    } else {
        Ok(vec![])
    }
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
    } else if httproute
        .metadata
        .annotations
        .as_ref()
        .and_then(|a_s| a_s.get(SKIP_VALIDATE_ANNOTATION))
        .is_some_and(|v| v == "true")
    {
        // TODO: Record the skipping event?
        ret.allowed = true;
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
        .is_none_or(|x| x.is_empty())
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
    mut ret: AdmissionResponse,
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

    let i = serde_json::to_value(ingress)?;
    let t = serde_json::to_value(target)?;
    let p = json_patch::diff(&i, &t);
    tracing::debug!("{p:?}");
    ret = ret.clone().with_patch(p)?;
    Ok(ret)
}

#[instrument]
pub async fn mutate_gateway(
    mut ret: AdmissionResponse,
    gateway: Gateway,
    conf: &Cli,
) -> AdmissionResponse {
    if gateway
        .metadata
        .annotations
        .as_ref()
        .and_then(|a_s| a_s.get(SKIP_MUTATE_ANNOTATION))
        .is_some_and(|v| v == "true")
    {
        // TODO: Record the skipping event?
        ret.allowed = true;
        return ret;
    }

    let mut target = gateway.clone();

    // If there is already non-redirect HTTPRoute attached to the HTTP listener,
    // Rework those listeners to HTTPS
    // TODO:
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
            .await
            .unwrap();
            tracing::debug!(
                "{} HTTPRoute-s are attached to this listener",
                httproutes.len()
            );
            let (_good, bad): (Vec<HTTPRoute>, Vec<HTTPRoute>) =
                httproutes.into_iter().partition(verify_httproute);
            if !bad.is_empty() {}
        }
    };

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
        // hostname and port are logically impossible to get.
        // Use 443 for port, althought this breaks Traefik,
        // which implementation is totally wrong.
        // Guess hostname from ExternalDNS annotation.
        let gn = gateway.metadata.name;
        let gns = gateway.metadata.namespace.as_ref().unwrap_or(
            DEFAULT_NAMESPACE
                .get()
                .expect("DEFAULT_NAMESPACE is not initialized"),
        );
        let hostname = gateway.metadata.annotations.and_then(|a_s| {
            a_s.get("external-dns.alpha.kubernetes.io/hostname")
                .map(|x| x.clone())
        });
        // gateway.spec.listeners.push(GatewayListeners {
        //     allowed_routes: None,
        //     hostname,
        //     name: "https".to_string(),
        //     port: 443,
        //     protocol: "HTTPS".to_string(),
        //     tls: Some(GatewayListenersTls {
        //         certificate_refs: Some(vec![GatewayListenersTlsCertificateRefs {
        //             group: None,
        //             kind: None,
        //             name: format!("{}-tls", gn.unwrap_or_default()),
        //             namespace: Some(gns.clone()),
        //         }]),
        //         mode: Some(GatewayListenersTlsMode::Terminate),
        //         options: None,
        //     }),
        // });
        // ret.with_patch(Patch(vec![if no_annotations {
        //     // Is there a better way to code this?
        //     PatchOperation::Add(AddOperation {
        //         path: annotation_path,
        //         value: annotations,
        //     })
        // } else {
        //     PatchOperation::Replace(ReplaceOperation {
        //         path: annotation_path,
        //         value: annotations,
        //     })
        // }]))
        // .map_err(|e| eyre!("{e:?}"));
    }

    ret
}

pub fn mutate_httproute(mut ret: AdmissionResponse, mut httproute: HTTPRoute) -> AdmissionResponse {
    todo!()
}
