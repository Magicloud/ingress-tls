use std::sync::Arc;

use eyre::Result;
use futures::{StreamExt, stream};
use gateway_api::{
    gateways::{Gateway, GatewayListeners},
    httproutes::{HTTPRoute, HTTPRouteParentRefs},
};
use kube::core::admission::AdmissionResponse;
use ouroboros::self_referencing;
use tracing::instrument;

#[allow(clippy::wildcard_imports)]
use crate::helpers::*;

// rewrite httproute to attach to same gateway's https listener, find by hostname, if possible. Or if there is only one.
#[instrument]
pub async fn validate_httproute(httproute: Arc<HTTPRoute>) -> Status {
    let checks: Vec<AsyncClosure<'_, Arc<HTTPRoute>>> = vec![
        // skip
        Box::new(|x| {
            Box::pin(async move {
                if x.metadata
                    .annotations
                    .as_ref()
                    .and_then(|a_s| a_s.get(SKIP_ANNOTATION))
                    .is_some_and(|v| v == "true")
                {
                    Ok(Status::Allowed)
                } else {
                    Ok(Status::MoveOn)
                }
            })
        }),
        // redirect
        Box::new(|x| {
            Box::pin(async move {
                if is_redirect_or_no_rule(&x) {
                    Ok(Status::Allowed)
                } else {
                    Ok(Status::MoveOn)
                }
            })
        }),
        // no parents yet
        Box::new(|x| {
            Box::pin(async move {
                if x.spec.parent_refs.is_none() {
                    Ok(Status::Allowed)
                } else {
                    Ok(Status::MoveOn)
                }
            })
        }),
        // attached to http listener
        Box::new(|x| {
            Box::pin(async move {
                let def_ns = "CLUSTERED".to_string();
                let parentrefs = x.spec.parent_refs.unwrap_ref();
                let httproute_namespace = x.metadata.namespace.as_ref().unwrap_or(&def_ns);
                let result = stream::iter(parentrefs)
                    .filter_map(|p| async {
                        filter_gateway_of_http_listener_attached_to(p, httproute_namespace)
                            .await
                            .transpose()
                    })
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect::<Result<Vec<_>>>();
                result.map(|glps| {
                    if glps.is_empty() {
                        Status::Allowed
                    } else {
                        Status::Denied(DenyReason::HTTPRouteNonRedirectAttachedToHTTPListener(glps))
                    }
                })
            })
        }),
    ];
    let mut accum = Status::MoveOn;
    for check in checks {
        let x = httproute.clone();
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

pub fn mutate_httproute(
    mut ret: AdmissionResponse,
    mut httproute: &HTTPRoute,
) -> AdmissionResponse {
    todo!()
}

#[instrument]
async fn filter_gateway_of_http_listener_attached_to(
    p: &HTTPRouteParentRefs,
    httproute_namespace: &str,
) -> Result<Option<GatewayListenerPair>> {
    let def_ns = "CLUSTERED".to_string();
    let empty_string = String::new();
    if p.kind.as_ref().is_some_and(|x| x == "Gateway") {
        let gateway = get_gateway(p.namespace.as_ref().unwrap_or(&def_ns), &p.name).await?;
        let ret = gateway.map(|g| {
            GatewayListenerPairBuilder {
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
            .build()
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
