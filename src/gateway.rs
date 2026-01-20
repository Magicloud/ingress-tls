use std::{collections::BTreeMap, sync::Arc};

use eyre::Result;
use futures::{StreamExt, stream};
use gateway_api::{
    gateways::{
        Gateway, GatewayListeners, GatewayListenersAllowedRoutes,
        GatewayListenersAllowedRoutesNamespaces, GatewayListenersAllowedRoutesNamespacesFrom,
        GatewayListenersTls, GatewayListenersTlsCertificateRefs, GatewayListenersTlsMode,
    },
    httproutes::HTTPRoute,
};
use itertools::Itertools;
use tracing::instrument;

#[allow(clippy::wildcard_imports)]
use crate::{cli::Cli, helpers::*};

// This is not enough. One could have a full gateway but only http (non-redirect) route.
// Once we have Gateway ready. Validate HTTPRoute.
// httproute should be (parent)http -> redirect, (parent)https -> allow.
// http one must only be redirect. So if no https route, accessing fails.
#[instrument(skip_all)]
pub fn validate_gateway<'a>() -> Checks<'a, Gateway, Option<Result<Status>>> {
    let x: Vec<AsyncClosure<'a, Gateway, Option<Result<Status>>>> = vec![
        // skip
        Box::new(|gateway| {
            Box::pin(async move {
                let skip = get_skip(gateway.as_ref())?;
                if skip == "true" {
                    Some(Ok(Status::Allowed))
                } else {
                    Some(Ok(Status::MoveOn))
                }
            })
        }),
        // non-redirect HTTPRoutes attached
        Box::new(|gateway| {
            Box::pin(async move {
                let ret = get_bad_httproutes_for_gateway(&gateway).await?.map(|bad| {
                    if bad.is_empty() {
                        Status::MoveOn
                    } else {
                        Status::Denied(
                            DenyReason::GatewayNonRedirectHTTPRouteAttachedToHTTPListener(
                                bad.into_iter().map(|(l, v)| (l.clone(), v)).collect(),
                            ),
                        )
                    }
                });
                Some(ret)
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
                    Some(Ok(Status::MoveOn))
                } else {
                    Some(Ok(Status::Denied(DenyReason::GatewayNoTLSListener)))
                }
            })
        }),
    ];
    x.into()
}

type ListenerHTTPRoutes<'a> = (&'a GatewayListeners, Parted<Vec<HTTPRoute>>);

#[instrument(skip_all)]
async fn get_bad_httproutes_for_gateway<'a>(
    gateway: &'a Gateway,
) -> Option<Result<Vec<ListenerHTTPRoutes<'a>>>> {
    let http_listeners = gateway
        .spec
        .listeners
        .iter()
        .filter(|l| l.protocol == "HTTP");
    let gateway_name = gateway.metadata.name.as_ref()?;
    let gateway_namespace = gateway.metadata.namespace.as_ref()?;

    let ret = stream::iter(http_listeners)
        .filter_map(|listener| async move {
            get_httproutes_for_listener(listener, gateway_name, gateway_namespace)
                .await?
                .map(|httproutes| {
                    tracing::debug!(
                        "{} HTTPRoute-s are attached to this listener",
                        httproutes.len()
                    );
                    let parted: (Vec<HTTPRoute>, Vec<HTTPRoute>) =
                        httproutes.into_iter().partition(is_redirect_or_no_rule);
                    if parted.1.is_empty() {
                        None
                    } else {
                        Some((
                            listener,
                            Parted {
                                good: parted.0,
                                bad: parted.1,
                            },
                        ))
                    }
                })
                .transpose()
        })
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>>>();

    Some(ret)
}

#[instrument(skip_all)]
async fn get_httproutes_for_listener(
    listener: &GatewayListeners,
    gateway_name: &str,
    gateway_namespace: &str,
) -> Option<Result<Vec<HTTPRoute>>> {
    let try_closure = || {
        let x = listener.allowed_routes.as_ref()?.namespaces.as_ref()?;
        Some(x)
    };
    let ns_sel = try_closure().unwrap_or(&GatewayListenersAllowedRoutesNamespaces {
        from: Some(GatewayListenersAllowedRoutesNamespacesFrom::Same),
        selector: None,
    });
    let namespaces: Result<Namespaces<'_>> = match ns_sel.from {
        Some(GatewayListenersAllowedRoutesNamespacesFrom::All) => Ok(Namespaces::All),
        Some(GatewayListenersAllowedRoutesNamespacesFrom::Selector) => {
            let s = ns_sel.selector.as_ref()?;
            let try_closure = || async {
                let m = s.match_expressions.as_ref().map_or(Ok(vec![]), |x| {
                    x.iter()
                        .map(|x| x.clone().try_into())
                        .collect::<Result<Vec<_>>>()
                })?;
                let empty_btreemap = BTreeMap::new();
                let mut l = s
                    .match_labels
                    .as_ref()
                    .unwrap_or(&empty_btreemap)
                    .iter()
                    .map(std::convert::Into::into)
                    .collect::<Vec<_>>();
                let mut selectors = m;
                selectors.append(&mut l);
                let nss = filter_namespaces(&selectors).await?;
                Ok(Namespaces::Some(
                    nss.into_iter().map(std::convert::Into::into).collect(),
                ))
            };
            try_closure().await
        }
        Some(GatewayListenersAllowedRoutesNamespacesFrom::Same) | None => {
            Ok(Namespaces::Some(vec![gateway_namespace.into()]))
        }
    };
    let try_closure = || async {
        let namespaces = namespaces?;
        tracing::debug!("{namespaces:?}");
        // Get HTTPRoutes that parentRef to this Gateway
        let httproutes = get_httproutes(&namespaces).await?;
        tracing::debug!("Totally {} HTTPRoutes found", httproutes.len());
        let x: Vec<HTTPRoute> = httproutes
            .into_iter()
            .filter_map(|httproute| {
                let hns = httproute.metadata.namespace.as_ref()?;
                if httproute
                    .spec
                    .parent_refs
                    .as_ref()?
                    .iter()
                    .all(|parentref| {
                        does_parentref_listener_match(
                            parentref,
                            listener,
                            gateway_name,
                            gateway_namespace,
                            hns,
                        )
                    })
                {
                    Some(httproute)
                } else {
                    None
                }
            })
            .collect();
        tracing::debug!("{} HTTPRoutes found for the listener", x.len());
        Ok(x)
    };

    let x = try_closure().await;
    Some(x)
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
#[instrument(skip_all)]
pub async fn mutate_gateway(gateway: Arc<Gateway>, conf: &Cli) -> Option<Result<Status>> {
    let validate_result = validate_gateway().run(gateway.clone()).await?;
    match validate_result {
        Ok(Status::Denied(DenyReason::GatewayNoTLSListener)) => {
            mutate_gateway_add_listeners(gateway.as_ref(), conf)
        }
        Ok(Status::Denied(DenyReason::GatewayNonRedirectHTTPRouteAttachedToHTTPListener(
            listener_parted_routes,
        ))) => mutate_gateway_convert_listeners(listener_parted_routes, gateway.as_ref()),
        _ => Some(validate_result),
    }
}

#[instrument(skip_all)]
fn mutate_gateway_add_listeners(gateway: &Gateway, conf: &Cli) -> Option<Result<Status>> {
    let port = if gateway.spec.gateway_class_name == "traefik" {
        8443
    } else {
        443
    };

    let mut target = (*gateway).clone();

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
    let gn = gateway.metadata.name.as_ref()?;
    let gns = gateway.metadata.namespace.as_ref()?;
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
    let mut annotations = target.metadata.annotations.take().unwrap_or_default();
    patch_annotations(&mut annotations, conf);
    target.metadata.annotations = Some(annotations);
    Some(patch(gateway, &target).map(Status::Patch))
}

#[instrument(skip_all)]
fn mutate_gateway_convert_listeners(
    listener_parted_routes: Vec<(GatewayListeners, Parted<Vec<HTTPRoute>>)>,
    gateway: &Gateway,
) -> Option<Result<Status>> {
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
    let gn = gateway.metadata.name.as_ref()?;
    let gns = gateway.metadata.namespace.as_ref()?;
    if inconvertible_listeners.is_empty() {
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
        Some(patch(gateway, &target).map(Status::Patch))
    } else {
        Some(Ok(Status::Denied(
            DenyReason::GatewayNonRedirectHTTPRouteAttachedToHTTPListener(listener_parted_routes),
        )))
    }
}

#[instrument(skip_all)]
fn patch_annotations(annotations: &mut BTreeMap<String, String>, conf: &Cli) {
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
