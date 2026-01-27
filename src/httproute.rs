use std::sync::Arc;

use eyre::Result;
use futures::{StreamExt, stream};
use gateway_api::{
    gateways::{Gateway, GatewayListeners},
    httproutes::{HTTPRoute, HTTPRouteParentRefs},
};
use itertools::Itertools;
use ouroboros::self_referencing;
use tracing::instrument;

#[allow(clippy::wildcard_imports)]
use crate::helpers::*;

#[instrument(skip_all)]
pub fn validate_httproute<'a>() -> Checks<'a, HTTPRoute, Option<Result<Status>>> {
    let x: Vec<AsyncClosure<'a, HTTPRoute, Option<Result<Status>>>> = vec![
        // skip
        Box::new(|httproute| {
            Box::pin(async move {
                let skip = get_skip(httproute.as_ref())?;
                if skip == "true" {
                    Some(Ok(Status::Allowed))
                } else {
                    Some(Ok(Status::MoveOn))
                }
            })
        }),
        // redirect
        Box::new(|httproute| {
            Box::pin(async move {
                if is_redirect_or_no_rule(httproute.as_ref()) {
                    Some(Ok(Status::Allowed))
                } else {
                    Some(Ok(Status::MoveOn))
                }
            })
        }),
        // no parents yet
        Box::new(|httproute| {
            Box::pin(async move {
                if httproute.spec.parent_refs.is_none() {
                    Some(Ok(Status::Allowed))
                } else {
                    Some(Ok(Status::MoveOn))
                }
            })
        }),
        // attached to http listener
        Box::new(|httproute| {
            Box::pin(async move {
                let parentrefs = httproute.spec.parent_refs.as_ref()?;
                let httproute_namespace = httproute.metadata.namespace.as_ref()?;
                let result = stream::iter(parentrefs)
                    .filter_map(|p| async {
                        filter_gateway_of_http_listener_attached_to(p, httproute_namespace)
                            .await
                            .map(|x| x.map(|y| (p.clone(), y)))
                    })
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>>>();
                Some(result.map(|glps| {
                    if glps.is_empty() {
                        Status::Allowed
                    } else {
                        Status::Denied(DenyReason::HTTPRouteNonRedirectAttachedToHTTPListener(glps))
                    }
                }))
            })
        }),
    ];
    x.into()
}

// rewrite httproute to attach to same gateway's https listener, find by hostname, if possible. Or if there is only one.
#[instrument(skip_all)]
pub async fn mutate_httproute(httproute: Arc<HTTPRoute>) -> Option<Result<Status>> {
    let validate_result = validate_httproute().run(httproute.clone()).await?;
    match validate_result {
        Ok(Status::Denied(DenyReason::HTTPRouteNonRedirectAttachedToHTTPListener(
            gateway_listener_pairs,
        ))) => {
            let mut target = (*httproute).clone();
            let bad_refs: Vec<_> = gateway_listener_pairs.iter().map(|(x, _)| x).collect();
            if let Some(ps) = target.spec.parent_refs.as_mut() {
                ps.retain(|p| !bad_refs.contains(&p));
            }
            let mut invalid = false;
            for (_, http_listener) in &gateway_listener_pairs {
                let gn = http_listener.borrow_gateway().metadata.name.as_ref()?;
                let gns = http_listener.borrow_gateway().metadata.namespace.as_ref()?;
                // 1. hostnames (http listener + route) match
                // 2. the only https listener
                let mut hostnames: Vec<&String> = httproute
                    .spec
                    .hostnames
                    .as_ref()
                    .map(|v| v.iter().collect())
                    .unwrap_or_default();
                hostnames.extend(
                    http_listener
                        .borrow_listeners()
                        .iter()
                        .filter_map(|l| l.hostname.as_ref()),
                );
                let hostnames: Vec<_> = hostnames.into_iter().unique().collect();

                let candidates = http_listener
                    .borrow_gateway()
                    .spec
                    .listeners
                    .iter()
                    .filter(|l| l.protocol == "HTTPS")
                    .collect::<Vec<_>>();
                if target.spec.parent_refs.is_none() {
                    target.spec.parent_refs = Some(vec![]);
                }

                if candidates.len() == 1 {
                    let listener = candidates.first()?;
                    if let Some(v) = target.spec.parent_refs.as_mut() {
                        v.push(HTTPRouteParentRefs {
                            group: None,
                            kind: Some("Gateway".to_string()),
                            name: gn.clone(),
                            namespace: Some(gns.clone()),
                            port: Some(listener.port),
                            section_name: Some(listener.name.clone()),
                        });
                    }
                } else if hostnames.iter().all(|h| {
                    candidates
                        .iter()
                        .any(|c| c.hostname.as_ref().is_some_and(|ch| ch == *h))
                }) {
                    // find https listeners that match all hostnames from routes and http listeners
                    let hostname_matches = candidates.iter().filter(|l| {
                        l.hostname
                            .as_ref()
                            .is_some_and(|lh| !lh.is_empty() && hostnames.contains(&lh))
                    });
                    for l in hostname_matches {
                        if let Some(v) = target.spec.parent_refs.as_mut() {
                            v.push(HTTPRouteParentRefs {
                                group: None,
                                kind: Some("Gateway".to_string()),
                                name: gn.clone(),
                                namespace: Some(gns.clone()),
                                port: Some(l.port),
                                section_name: Some(l.name.clone()),
                            });
                        }
                    }
                } else {
                    invalid = true;
                    break;
                }
            }
            if invalid {
                Some(Ok(Status::Denied(
                    DenyReason::HTTPRouteNonRedirectAttachedToHTTPListener(gateway_listener_pairs),
                )))
            } else {
                Some(patch(httproute.as_ref(), &target).map(Status::Patch))
            }
        }
        _ => Some(validate_result),
    }
}

// TODO: filter on gateway side, the allowed routes
#[instrument(skip_all)]
async fn filter_gateway_of_http_listener_attached_to(
    p: &HTTPRouteParentRefs,
    httproute_namespace: &str,
) -> Option<Result<GatewayListenerPair>> {
    if p.kind.as_ref().is_some_and(|x| x == "Gateway") {
        let gateway = get_gateway(
            p.namespace
                .as_ref()
                .map_or(httproute_namespace, |s| s.as_str()),
            &p.name,
        )
        .await
        .transpose()?;
        match gateway {
            Ok(gateway) => {
                let gn = gateway.metadata.name.clone()?;
                let gns = gateway.metadata.namespace.clone()?;
                let glp = GatewayListenerPairBuilder {
                    gateway,
                    listeners_builder: |gateway| {
                        gateway
                            .spec
                            .listeners
                            .iter()
                            .filter(|listener| {
                                listener.protocol == "HTTP"
                                    && does_parentref_listener_match(
                                        p,
                                        listener,
                                        &gn,
                                        &gns,
                                        httproute_namespace,
                                    )
                            })
                            .collect()
                    },
                }
                .build();
                if glp.borrow_listeners().is_empty() {
                    None
                } else {
                    Some(Ok(glp))
                }
            }
            Err(e) => Some(Err(e)),
        }
    } else {
        None
    }
}

#[self_referencing]
#[derive(Debug)]
pub struct GatewayListenerPair {
    pub gateway: Gateway,
    #[borrows(gateway)]
    #[covariant]
    pub listeners: Vec<&'this GatewayListeners>,
}
