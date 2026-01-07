use std::{collections::BTreeMap, sync::Arc};

use eyre::Result;
use gateway_api::{
    gateways::{
        Gateway, GatewayListeners, GatewayListenersAllowedRoutes,
        GatewayListenersAllowedRoutesNamespaces, GatewayListenersAllowedRoutesNamespacesFrom,
        GatewayListenersTls, GatewayListenersTlsCertificateRefs, GatewayListenersTlsMode,
    },
    httproutes::HTTPRoute,
};
use itertools::Itertools;
use just_string::JustString;
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
                    .and_then(|a_s| a_s.get(SKIP_ANNOTATION))
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
                let bad = get_bad_httproutes_for_gateway(&x).await?;
                if bad.is_empty() {
                    Ok(Status::MoveOn)
                } else {
                    Ok(Status::Denied(
                        DenyReason::GatewayNonRedirectHTTPRouteAttachedToHTTPListener(
                            bad.into_iter().map(|(l, v)| (l.clone(), v)).collect(),
                        ),
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

type ListenerHTTPRoutes<'a> = (&'a GatewayListeners, Parted<Vec<HTTPRoute>>);
#[instrument]
async fn get_bad_httproutes_for_gateway<'a>(
    gateway: &'a Gateway,
) -> Result<Vec<ListenerHTTPRoutes<'a>>> {
    let http_listeners = gateway
        .spec
        .listeners
        .iter()
        .filter(|l| l.protocol == "HTTP");
    let def_ns = "CLUSTERED".to_string();
    if let Some(ref gateway_name) = gateway.metadata.name {
        let mut ret = vec![];
        for (i, listener) in http_listeners.enumerate() {
            tracing::debug!("Working on listener {i}: {}", listener.name,);
            let httproutes = get_httproutes_for_listener(
                listener,
                gateway_name,
                gateway.metadata.namespace.as_ref().unwrap_or(&def_ns),
            )
            .await?;
            tracing::debug!(
                "{} HTTPRoute-s are attached to this listener",
                httproutes.len()
            );
            let parted: (Vec<HTTPRoute>, Vec<HTTPRoute>) =
                httproutes.into_iter().partition(is_redirect_or_no_rule);
            if !parted.1.is_empty() {
                ret.push((
                    listener,
                    Parted {
                        good: parted.0,
                        bad: parted.1,
                    },
                ));
            }
        }
        Ok(ret)
    } else {
        Ok(vec![])
    }
}

#[instrument]
async fn get_httproutes_for_listener(
    listener: &GatewayListeners,
    gateway_name: &str,
    gateway_namespace: &str,
) -> Result<Vec<HTTPRoute>> {
    let def_ns = "CLUSTERED".to_string();
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
                let hns = httproute.metadata.namespace.as_ref().unwrap_or(&def_ns);
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
pub async fn mutate_gateway(gateway: Arc<Gateway>, conf: &Cli) -> Status {
    match validate_gateway(gateway.clone()).await {
        Status::Allowed => Status::Allowed,
        Status::Denied(deny_reason) => match deny_reason {
            DenyReason::InternalError(ref _r) => Status::Denied(deny_reason),
            DenyReason::GatewayNoTLSListener => {
                mutate_gateway_add_listeners(gateway.as_ref(), conf)
            }
            DenyReason::GatewayNonRedirectHTTPRouteAttachedToHTTPListener(
                listener_parted_routes,
            ) => mutate_gateway_convert_listeners(listener_parted_routes, gateway.as_ref(), conf),
            _ => unimplemented!(),
        },
        _ => unimplemented!(),
    }
}

#[instrument]
fn mutate_gateway_add_listeners(gateway: &Gateway, conf: &Cli) -> Status {
    let port = if gateway.spec.gateway_class_name == "traefik" {
        8443
    } else {
        443
    };

    let mut target = (*gateway).clone();

    let def_ns = "CLUSTERED".to_string();
    let edns_hostnames = get_external_dns_hostname(gateway).unwrap_or_default();
    let mut hostnames = gateway
        .spec
        .listeners
        .iter()
        .filter_map(|x| x.hostname.as_ref())
        .collect::<Vec<_>>();
    hostnames.extend(edns_hostnames.iter());
    let hostnames = hostnames.into_iter().unique();
    // Running to this reason, means there is no non-redirect httproute attached.
    // How to guarantee?
    if let Some(gn) = gateway.metadata.name.as_ref()
        && let Some(gns) = gateway.metadata.namespace.as_ref()
    {
        for hostname in hostnames {
            target.spec.listeners.push(GatewayListeners {
                allowed_routes: Some(GatewayListenersAllowedRoutes {
                    kinds: None,
                    namespaces: Some(GatewayListenersAllowedRoutesNamespaces {
                        from: Some(GatewayListenersAllowedRoutesNamespacesFrom::Same),
                        selector: None,
                    }),
                }),
                hostname: Some(hostname.clone()),
                name: format!("{gn}-https"),
                port,
                protocol: "HTTPS".to_string(),
                tls: Some(GatewayListenersTls {
                    certificate_refs: Some(vec![GatewayListenersTlsCertificateRefs {
                        group: None,
                        kind: None,
                        name: format!("{gn}-https-tls"),
                        namespace: Some(gns.clone()),
                    }]),
                    mode: Some(GatewayListenersTlsMode::Terminate),
                    options: None,
                }),
            });
        }
        let ns = gateway.metadata.namespace.as_ref().unwrap_or(&def_ns);
        let mut annotations = target.metadata.annotations.take().unwrap_or_default();
        patch_annotations(&mut annotations, ns, conf);
        target.metadata.annotations = Some(annotations);
        match patch(gateway, &target) {
            Ok(p) => Status::Patch(p),
            Err(e) => Status::Denied(DenyReason::InternalError(e)),
        }
    } else {
        Status::Invalid("Could not get enough information to assemble a HTTPS listener".to_string())
    }
}

#[instrument]
fn mutate_gateway_convert_listeners(
    listener_parted_routes: Vec<(GatewayListeners, Parted<Vec<HTTPRoute>>)>,
    gateway: &Gateway,
    conf: &Cli,
) -> Status {
    let port = if gateway.spec.gateway_class_name == "traefik" {
        8443
    } else {
        443
    };

    let mut target = (*gateway).clone();
    // The HTTP listener is used by both non-redirect and regular
    // HTTPRoutes. Cannot convert this to HTTPS.
    // The the listener does not contain a hostname.
    let (convertible_listeners, inconvertible_listeners): (Vec<_>, Vec<_>) =
        listener_parted_routes.iter().partition(|(li, v)| {
            v.good.is_empty()
                && target
                    .spec
                    .listeners
                    .iter()
                    .find(|l| l.name == li.name)
                    .is_some_and(|l| l.hostname.as_ref().is_some_and(|x| !x.is_empty()))
        });
    if let Some(gn) = gateway.metadata.name.as_ref()
        && let Some(gns) = gateway.metadata.namespace.as_ref()
        && inconvertible_listeners.is_empty()
    {
        for (li, _) in convertible_listeners {
            target.spec.listeners.iter_mut().for_each(|l| {
                if l.name == li.name {
                    l.protocol = "HTTPS".to_string();
                    l.tls = Some(GatewayListenersTls {
                        certificate_refs: Some(vec![GatewayListenersTlsCertificateRefs {
                            group: None,
                            kind: None,
                            name: format!("{gn}-{}-tls", l.name),
                            namespace: Some(gns.clone()),
                        }]),
                        mode: Some(GatewayListenersTlsMode::Terminate),
                        options: None,
                    });
                    l.port = port;
                }
            });
        }
        match patch(gateway, &target) {
            Ok(p) => Status::Patch(p),
            Err(e) => Status::Denied(DenyReason::InternalError(e)),
        }
    } else {
        Status::Denied(
            DenyReason::GatewayNonRedirectHTTPRouteAttachedToHTTPListener(listener_parted_routes),
        )
    }
}

#[instrument]
fn patch_annotations(annotations: &mut BTreeMap<String, String>, ns: &str, conf: &Cli) {
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
}
