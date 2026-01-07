use std::{collections::HashMap, sync::Arc};

use eyre::Result;
use gateway_api::{
    gateways::{
        Gateway, GatewayListeners, GatewayListenersAllowedRoutes,
        GatewayListenersAllowedRoutesNamespaces, GatewayListenersAllowedRoutesNamespacesFrom,
        GatewayListenersTls, GatewayListenersTlsCertificateRefs, GatewayListenersTlsMode,
    },
    httproutes::{HTTPRoute, HTTPRouteParentRefs},
};
use just_string::JustString;
use kube::core::admission::AdmissionResponse;
use serde::Serialize;
use tracing::instrument;

#[allow(clippy::wildcard_imports)]
use crate::{cli::Cli, helpers::*};

// This is not enough. One could have a full gateway but only http (non-redirect) route.
// Once we have Gateway ready. Validate HTTPRoute.
// httproute should be (parent)http -> redirect, (parent)https -> allow.
// http one must only be redirect. So if no https route, accessing fails.
#[instrument]
pub async fn validate_gateway(gateway: Arc<Gateway>) -> Status {
    let checks: Vec<AsyncClosure<'_, Arc<Gateway>>> = vec![
        // skip
        Box::new(|x| {
            Box::pin(async move {
                if x.metadata
                    .annotations
                    .as_ref()
                    .and_then(|a_s| a_s.get(SKIP_VALIDATE_ANNOTATION))
                    .is_some_and(|v| v == "true")
                {
                    Ok(Status::Allowed) as Result<Status>
                } else {
                    Ok(Status::MoveOn)
                }
            })
        }),
        // non-redirect HTTPRoutes attached
        Box::new(|x| {
            Box::pin(async move {
                let bad = get_bad_httproute_for_gateway(&x).await?;
                if bad.is_empty() {
                    Ok(Status::MoveOn)
                } else {
                    Ok(Status::Denied(
                        DenyReason::GatewayNonRedirectHTTPRouteAttached(bad),
                    )) as Result<Status>
                }
            })
        }),
        // no TLS listener
        Box::new(|x| {
            Box::pin(async move {
                if x.spec.listeners.iter().any(|l| l.protocol == "HTTPS")
                // `HTTPS` without `tls` is invalid, won't be programmed.
                // Hence it is reasonable not checking the following.
                // && let Some(ref tls) = listener.tls
                // && (tls.mode == Some(GatewayListenersTlsMode::Passthrough)
                //     || (tls.mode == Some(GatewayListenersTlsMode::Terminate)
                //         && tls.certificate_refs.is_some()
                //         && !tls.certificate_refs.as_ref().unwrap().is_empty()))
                {
                    Ok(Status::MoveOn) as Result<Status>
                } else {
                    Ok(Status::Denied(DenyReason::GatewayNoTLSListener))
                }
            })
        }),
    ];
    let mut accum = Status::MoveOn;
    for check in checks {
        let x = gateway.clone();
        let ret = match accum {
            Status::MoveOn => match check(x).await {
                Ok(x) => Ok(x),
                Err(e) => Err(Status::Denied(DenyReason::InternalError(e))),
            },
            x => Err(x),
        };
        let is_err = ret.is_err();
        accum = ret.extract();
        if is_err {
            break;
        }
    }
    accum
}

#[instrument]
async fn get_bad_httproute_for_gateway(
    gateway: &Gateway,
) -> Result<HashMap<ListenerIdentifier, Vec<HTTPRoute>>> {
    let http_listeners = gateway
        .spec
        .listeners
        .iter()
        .filter(|l| l.protocol == "HTTP");
    let def_ns = DEFAULT_NAMESPACE
        .get()
        .expect("Cannot get DEFAULT_NAMESPACE");
    if let Some(ref gateway_name) = gateway.metadata.name {
        let mut ret = HashMap::new();
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
            let bad = httproutes
                .into_iter()
                .filter(|x| !is_redirect_or_no_rule(x))
                .collect();
            ret.insert(listener.into(), bad);
        }
        Ok(ret)
    } else {
        Ok(HashMap::new())
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
                // TODO: the result is intersection, not union.
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
                        does_parentref_listener_match(
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

// Gateway: Add HTTPS protocol listener. Need hostname and port.
// If a httproute is refing the HTTP listener, rework the listener to HTTPS.
// There would be two issues.
// 1. There are already HTTPS listeners.
// 2. There are redirect as well.
// If http listener is 80(8000), assume https is 443(8443), otherwise fails.
// When a non-redirect http route comes in, turn it into https section.
// If there is no redirect http route after all, not so bad.
// hostname and port are logically impossible to get.
// Guess hostname from ExternalDNS annotation. Or from http listener.
#[instrument]
pub async fn mutate_gateway(
    mut ret: AdmissionResponse,
    gateway: &Gateway,
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
    let hostname = gateway
        .metadata
        .annotations
        .as_ref()
        .and_then(|a_s| a_s.get("external-dns.alpha.kubernetes.io/hostname"));
    if let Some(ref _name) = gateway.metadata.name {
        // Is this a good idea? Precheck necessary data here, following steps
        // could just unwrap.
    } else {
        return AdmissionResponse::invalid("The Gateway does not contain enough information");
    }

    let def_ns = DEFAULT_NAMESPACE
        .get()
        .expect("Cannot get DEFAULT_NAMESPACE");
    let mut target = gateway.clone();

    // If there is already non-redirect HTTPRoute attached to the HTTP listener,
    // Rework those listeners to HTTPS
    let http_listeners = target
        .spec
        .listeners
        .iter_mut()
        .filter(|l| l.protocol == "HTTP");
    let gn = gateway.metadata.name.unwrap_ref();
    let gns = gateway.metadata.namespace.as_ref().unwrap_or(def_ns);
    let mut edited = false;
    for (i, listener) in http_listeners.enumerate() {
        tracing::debug!("Working on listener {i}: {}", listener.name,);
        let httproutes = get_httproutes_for_listener(listener, gn, gns)
            .await
            .unwrap();
        tracing::debug!(
            "{} HTTPRoute-s are attached to this listener",
            httproutes.len()
        );
        if httproutes.into_iter().any(|x| !is_redirect_or_no_rule(&x)) {
            edited = true;
            listener.protocol = "HTTPS".to_string();
            listener.port = match listener.port {
                80 => 443,
                8000 => 8443,
                _ => {
                    return AdmissionResponse::invalid("Cannot infer port number for TLS");
                }
            };
            if listener
                .hostname
                .as_ref()
                .is_none_or(std::string::String::is_empty)
            {
                if let Some(h) = hostname {
                    listener.hostname = Some(h.clone());
                } else {
                    return AdmissionResponse::invalid("Cannot infer hostname for TLS");
                }
            }
            listener.tls = Some(GatewayListenersTls {
                certificate_refs: Some(vec![GatewayListenersTlsCertificateRefs {
                    group: None,
                    kind: None,
                    name: format!("{gn}-tls"),
                    namespace: Some(gns.clone()),
                }]),
                mode: Some(GatewayListenersTlsMode::Terminate),
                options: None,
            });
        }
    }
    // If we reworked, there is already tls in gateway, return the patch.
    if edited {
        match patch(gateway, &target, ret.clone()) {
            Ok(ret) => return ret,
            Err(e) => return ret.deny(format!("{e:?}")),
        }
    }
    // If we did not rework, check if tls is there.

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
        ret.allowed = true;
    } else {
        let hostname = if let Some(h) = hostname {
            Some(h.clone())
        } else {
            todo!()
        };
        let port = if gateway.spec.gateway_class_name == "traefik" {
            8443
        } else {
            443
        };
        target.spec.listeners.push(GatewayListeners {
            allowed_routes: Some(GatewayListenersAllowedRoutes {
                kinds: None,
                namespaces: Some(GatewayListenersAllowedRoutesNamespaces {
                    from: Some(GatewayListenersAllowedRoutesNamespacesFrom::Same),
                    selector: None,
                }),
            }),
            hostname,
            name: format!("{gn}-tls"),
            port,
            protocol: "HTTPS".to_string(),
            tls: Some(GatewayListenersTls {
                certificate_refs: Some(vec![GatewayListenersTlsCertificateRefs {
                    group: None,
                    kind: None,
                    name: format!("{gn}-tls"),
                    namespace: Some(gns.clone()),
                }]),
                mode: Some(GatewayListenersTlsMode::Terminate),
                options: None,
            }),
        });
        match patch(gateway, &target, ret) {
            Ok(_) => todo!(),
            Err(_) => todo!(),
        }
    }

    ret
}

fn patch<T: Serialize>(src: &T, dst: &T, ret: AdmissionResponse) -> Result<AdmissionResponse> {
    let s = serde_json::to_value(src)?;
    let d = serde_json::to_value(dst)?;
    let p = json_patch::diff(&s, &d);
    let x = ret.with_patch(p)?;
    Ok(x)
}
