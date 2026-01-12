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

#[instrument]
pub async fn validate_httproute(httproute: Arc<HTTPRoute>) -> Status {
    let checks = todo!();
    // let checks: Vec<AsyncClosure<'_, Arc<HTTPRoute>>> = vec![
    //     // skip
    //     Box::new(|x| {
    //         Box::pin(async move {
    //             if x.metadata
    //                 .annotations
    //                 .as_ref()
    //                 .and_then(|a_s| a_s.get(SKIP_ANNOTATION))
    //                 .is_some_and(|v| v == "true")
    //             {
    //                 Ok(Status::Allowed)
    //             } else {
    //                 Ok(Status::MoveOn)
    //             }
    //         })
    //     }),
    //     // redirect
    //     Box::new(|x| {
    //         Box::pin(async move {
    //             if is_redirect_or_no_rule(&x) {
    //                 Ok(Status::Allowed)
    //             } else {
    //                 Ok(Status::MoveOn)
    //             }
    //         })
    //     }),
    //     // no parents yet
    //     Box::new(|x| {
    //         Box::pin(async move {
    //             if x.spec.parent_refs.is_none() {
    //                 Ok(Status::Allowed)
    //             } else {
    //                 Ok(Status::MoveOn)
    //             }
    //         })
    //     }),
    //     // attached to http listener
    //     Box::new(|x| {
    //         Box::pin(async move {
    //             let def_ns = "CLUSTERED".to_string();
    //             let parentrefs = x.spec.parent_refs.unwrap_ref();
    //             let httproute_namespace = x.metadata.namespace.as_ref().unwrap_or(&def_ns);
    //             let result = stream::iter(parentrefs)
    //                 .filter_map(|p| async {
    //                     filter_gateway_of_http_listener_attached_to(p, httproute_namespace)
    //                         .await
    //                         .transpose()
    //                         .map(|x| x.map(|y| (p.clone(), y)))
    //                 })
    //                 .collect::<Vec<_>>()
    //                 .await
    //                 .into_iter()
    //                 .collect::<Result<Vec<_>>>();
    //             result.map(|glps| {
    //                 if glps.is_empty() {
    //                     Status::Allowed
    //                 } else {
    //                     Status::Denied(DenyReason::HTTPRouteNonRedirectAttachedToHTTPListener(glps))
    //                 }
    //             })
    //         })
    //     }),
    // ];
    // let mut accum = Status::MoveOn;
    // for check in checks {
    //     let x = httproute.clone();
    //     let ret = match accum {
    //         Status::MoveOn => match check(x).await {
    //             Ok(x) => Ok(x),
    //             Err(e) => Err(Status::Denied(DenyReason::InternalError(e))),
    //         },
    //         x => Err(x),
    //     };
    //     let is_err = ret.is_err();
    //     accum = ret.extract();
    //     if is_err {
    //         break;
    //     }
    // }
    // accum
}

// rewrite httproute to attach to same gateway's https listener, find by hostname, if possible. Or if there is only one.
#[instrument]
pub async fn mutate_httproute(httproute: Arc<HTTPRoute>) -> Status {
    let mut target = (*httproute).clone();
    match validate_httproute(httproute.clone()).await {
        Status::Allowed => Status::Allowed,
        Status::Denied(deny_reason) => match deny_reason {
            DenyReason::InternalError(ref _r) => Status::Denied(deny_reason),
            DenyReason::HTTPRouteNonRedirectAttachedToHTTPListener(gateway_listener_pairs) => {
                let bad_refs: Vec<_> = gateway_listener_pairs.iter().map(|(x, _)| x).collect();
                if let Some(ps) = target.spec.parent_refs.as_mut() {
                    ps.retain(|p| !bad_refs.contains(&p));
                }
                for (_, http_listener) in gateway_listener_pairs {
                    // gateway is matched by name/namespace. hence following two vars must be there.
                    let gn = http_listener
                        .borrow_gateway()
                        .metadata
                        .name
                        .as_ref()
                        .unwrap();
                    let gns = http_listener
                        .borrow_gateway()
                        .metadata
                        .namespace
                        .as_ref()
                        .unwrap();
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
                        let listener = candidates.first().unwrap();
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
                        // invalid
                    }
                }
                match patch(httproute.as_ref(), &target) {
                    Ok(_) => todo!(),
                    Err(_) => todo!(),
                }
            }
            _ => unimplemented!(),
        },
        _ => unimplemented!(),
    }
}

// TODO: filter on gateway side, the allowed routes
#[instrument]
async fn filter_gateway_of_http_listener_attached_to(
    p: &HTTPRouteParentRefs,
    httproute_namespace: &str,
) -> Result<Option<GatewayListenerPair>> {
    let def_ns = "CLUSTERED".to_string();
    let empty_string = String::new();
    if p.kind.as_ref().is_some_and(|x| x == "Gateway") {
        let gateway = get_gateway(p.namespace.as_ref().unwrap_or(&def_ns), &p.name).await?;
        let ret = gateway.and_then(|g| {
            let glp = GatewayListenerPairBuilder {
                gateway: g,
                listeners_builder: |gateway| {
                    let gn = gateway.metadata.name.as_ref().unwrap_or(&empty_string);
                    let gns = gateway.metadata.namespace.as_ref().unwrap_or(&def_ns);
                    gateway
                        .spec
                        .listeners
                        .iter()
                        .filter(|listener| {
                            listener.protocol == "HTTP"
                                && does_parentref_listener_match(
                                    p,
                                    listener,
                                    gn,
                                    gns,
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
                Some(glp)
            }
        });
        Ok(ret)
    } else {
        Ok(None)
    }
}

#[self_referencing]
pub struct GatewayListenerPair {
    pub gateway: Gateway,
    #[borrows(gateway)]
    #[covariant]
    pub listeners: Vec<&'this GatewayListeners>,
}
