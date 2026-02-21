use std::{borrow::Cow, fmt::Display, str::FromStr, sync::Arc};

use eyre::{Report, Result, eyre};
use futures::future::BoxFuture;
use gateway_api::{
    gateways::{
        Gateway, GatewayListeners, GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions,
    },
    httproutes::{
        HTTPRoute, HTTPRouteParentRefs, HTTPRouteRules, HTTPRouteRulesFilters,
        HTTPRouteRulesFiltersRequestRedirect, HTTPRouteRulesFiltersRequestRedirectScheme,
        HTTPRouteRulesFiltersType, HTTPRouteRulesMatches, HTTPRouteRulesMatchesPath,
        HTTPRouteRulesMatchesPathType,
    },
};
use itertools::Itertools;
use json_patch::Patch;
use k8s_openapi::api::{core::v1::Namespace, networking::v1::Ingress};
use kube::{
    Api, Client,
    api::{DynamicObject, ListParams, ObjectMeta},
    core::admission::AdmissionResponse,
};
use serde::Serialize;
use tracing::instrument;

use crate::httproute::GatewayListenerPair;

pub const SKIP_ANNOTATION: &str = "ingress-tls.magiclouds.cn/skip";
pub const TRAEFIK_MIDDLEWARE_ANNOTATION: &str = "traefik.ingress.kubernetes.io/router.middlewares";
pub const NGINX_FORCE_SSL_REDIRECT: &str = "nginx.ingress.kubernetes.io/force-ssl-redirect";
pub const ISSUER: &str = "cert-manager.io/issuer";
pub const CLUSTER_ISSUER: &str = "cert-manager.io/cluster-issuer";
pub const ISSUER_KIND: &str = "cert-manager.io/issuer-kind";
pub const ISSUER_GROUP: &str = "cert-manager.io/issuer-group";

#[allow(unused_macros)]
macro_rules! debug_cond {
    ($cond:expr) => {{
        let result = $cond;
        if !result {
            tracing::debug!(
                "[{}:{}] Condition failed: {}",
                file!(),
                line!(),
                stringify!($cond)
            );
        }
        result
    }};
}

// Why this is not a Trait for all objects.
pub fn dynamic_object2ingress(obj: DynamicObject) -> Result<Ingress> {
    let mut obj = obj;
    Ok(Ingress {
        metadata: obj.metadata,
        spec: obj
            .data
            .get_mut("spec")
            .map(|spec| serde_json::from_value(spec.take()))
            .transpose()?,
        status: obj
            .data
            .get_mut("status")
            .map(|status| serde_json::from_value(status.take()))
            .transpose()?,
    })
}

pub fn dynamic_object2gateway(obj: DynamicObject) -> Result<Gateway> {
    let mut obj = obj;
    Ok(Gateway {
        metadata: obj.metadata,
        spec: obj
            .data
            .get_mut("spec")
            .ok_or_else(|| eyre!("No spec provided"))
            .and_then(|spec| serde_json::from_value(spec.take()).map_err(|e| eyre!("{e:?}")))?,
        status: obj
            .data
            .get_mut("status")
            .map(|status| serde_json::from_value(status.take()))
            .transpose()?,
    })
}

pub fn dynamic_object2httproute(obj: DynamicObject) -> Result<HTTPRoute> {
    let mut obj = obj;
    Ok(HTTPRoute {
        metadata: obj.metadata,
        spec: obj
            .data
            .get_mut("spec")
            .ok_or_else(|| eyre!("No spec provided"))
            .and_then(|spec| serde_json::from_value(spec.take()).map_err(|e| eyre!("{e:?}")))?,
        status: obj
            .data
            .get_mut("status")
            .map(|status| serde_json::from_value(status.take()))
            .transpose()?,
    })
}

#[derive(Debug)]
pub enum SupportedIngressClass {
    Traefik,
    Nginx,
}
impl FromStr for SupportedIngressClass {
    type Err = eyre::Report;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s = s.to_lowercase();
        if s == "traefik" {
            Ok(Self::Traefik)
        } else if s == "nginx" {
            Ok(Self::Nginx)
        } else {
            Err(eyre!("Unsupported Ingress Class"))
        }
    }
}

#[derive(Debug, Clone)]
pub enum Issuer {
    Namespaced(String),
    Clustered(String),
}

pub async fn get_gateway(namespace: &str, name: &str) -> Result<Option<Gateway>> {
    let client = Client::try_default().await?;
    let gateways: Api<Gateway> = Api::namespaced(client, namespace);
    let gateway = gateways.get_opt(name).await?;
    Ok(gateway)
}

pub async fn get_httproutes(namesapces: &Namespaces<'_>) -> Result<Vec<HTTPRoute>> {
    let client = Client::try_default().await?;
    let httproute: Vec<Api<HTTPRoute>> = match namesapces {
        Namespaces::All => {
            let ns: Api<Namespace> = Api::all(client.clone());
            let namespaces = ns.list(&ListParams::default()).await?;
            namespaces
                .items
                .into_iter()
                .filter_map(|x| {
                    x.metadata
                        .name
                        .map(|ns| Api::namespaced(client.clone(), &ns))
                })
                .collect()
        }
        Namespaces::Some(items) => items
            .iter()
            .map(|ns| Api::namespaced(client.clone(), ns))
            .collect(),
    };
    let lp = ListParams::default();
    let mut ret = Vec::new();
    for api in httproute {
        let httproutes = api.list(&lp).await?;
        for i in httproutes.items {
            if let Some(name) = i.metadata.name {
                let httproute = api.get(&name).await?;
                ret.push(httproute);
            }
        }
    }
    Ok(ret)
}

pub async fn filter_namespaces(selectors: &[SelectorByLabel<'_, '_>]) -> Result<Vec<String>> {
    let client = Client::try_default().await?;
    let namespaces: Api<Namespace> = Api::all(client);
    let lp = ListParams {
        label_selector: Some(
            selectors
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ),
        ..Default::default()
    };
    Ok(namespaces
        .list(&lp)
        .await?
        .items
        .into_iter()
        .filter_map(|x| x.metadata.name)
        .collect())
}

#[derive(Debug)]
pub enum Namespaces<'a> {
    All,
    Some(Vec<Cow<'a, str>>),
}

#[allow(dead_code)]
pub enum SelectorByLabel<'a, 'b> {
    Is(Cow<'a, str>, Cow<'b, str>),
    IsNot(Cow<'a, str>, Cow<'b, str>),
    In(Cow<'a, str>, Vec<Cow<'b, str>>),
    NotIn(Cow<'a, str>, Vec<Cow<'b, str>>),
    Exists(Cow<'a, str>),
    DoesNotExist(Cow<'a, str>),
}
impl Display for SelectorByLabel<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::In(k, v) => f.write_str(&format!("{k} in ({})", v.join(","))),
            Self::NotIn(k, v) => f.write_str(&format!("{k} notin ({})", v.join(","))),
            Self::Exists(k) => f.write_str(k),
            Self::DoesNotExist(k) => f.write_str(&format!("!{k}")),
            Self::Is(k, v) => f.write_str(&format!("{k}={v}")),
            Self::IsNot(k, v) => f.write_str(&format!("{k}!={v}")),
        }
    }
}
impl From<(String, String)> for SelectorByLabel<'_, '_> {
    fn from(value: (String, String)) -> Self {
        Self::Is(value.0.into(), value.1.into())
    }
}
impl<'a> From<(&'a String, String)> for SelectorByLabel<'a, '_> {
    fn from(value: (&'a String, String)) -> Self {
        Self::Is(value.0.into(), value.1.into())
    }
}
impl<'b> From<(String, &'b String)> for SelectorByLabel<'_, 'b> {
    fn from(value: (String, &'b String)) -> Self {
        Self::Is(value.0.into(), value.1.into())
    }
}
impl<'a, 'b> From<(&'a String, &'b String)> for SelectorByLabel<'a, 'b> {
    fn from(value: (&'a String, &'b String)) -> Self {
        Self::Is(value.0.into(), value.1.into())
    }
}
impl TryFrom<GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions>
    for SelectorByLabel<'_, '_>
{
    type Error = Report;

    fn try_from(
        value: GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions,
    ) -> std::result::Result<Self, Self::Error> {
        let ret = if value.operator == "In" {
            Self::In(
                value.key.into(),
                value
                    .values
                    .ok_or_else(|| eyre!("`values` should be supplied in `In` operation"))?
                    .into_iter()
                    .map(std::convert::Into::into)
                    .collect(),
            )
        } else if value.operator == "NotIn" {
            Self::NotIn(
                value.key.into(),
                value
                    .values
                    .ok_or_else(|| eyre!("`values` should be supplied in `NotIn` operation"))?
                    .into_iter()
                    .map(std::convert::Into::into)
                    .collect(),
            )
        } else if value.operator == "Exists" {
            Self::Exists(value.key.into())
        } else if value.operator == "DoesNotExist" {
            Self::DoesNotExist(value.key.into())
        } else {
            return Err(eyre!("Invalid operator {}", value.operator));
        };
        Ok(ret)
    }
}

pub fn patch<T: Serialize>(src: &T, dst: &T) -> Result<Patch> {
    let s = serde_json::to_value(src)?;
    let d = serde_json::to_value(dst)?;
    let p = json_patch::diff(&s, &d);
    Ok(p)
}

#[derive(Debug)]
pub enum Status {
    MoveOn,
    Allowed,
    Denied(DenyReason),
    Invalid(String),
    Patch(Patch),
}
impl From<Option<Result<Self>>> for Status {
    fn from(value: Option<Result<Self>>) -> Self {
        match value {
            Some(Ok(s)) => s,
            Some(Err(e)) => {
                tracing::warn!(target: "internal-error", message = format!("{e:?}"));
                Self::Denied(DenyReason::InternalError(e))
            }
            None => Self::Invalid("Input does not contain enough information".to_string()),
        }
    }
}

pub struct StatusAdmissionResponse(Status, AdmissionResponse, (String, String));
impl From<(Status, AdmissionResponse, (&String, &String))> for StatusAdmissionResponse {
    fn from(value: (Status, AdmissionResponse, (&String, &String))) -> Self {
        Self(value.0, value.1, (value.2.0.clone(), value.2.1.clone()))
    }
}
impl From<StatusAdmissionResponse> for AdmissionResponse {
    fn from(StatusAdmissionResponse(s, mut a, m): StatusAdmissionResponse) -> Self {
        match s {
            Status::Allowed | Status::MoveOn => {
                a.allowed = true;
                a
            }
            Status::Denied(msg) => a.deny(format!("{}/{}: {msg}", m.0, m.1)),
            Status::Invalid(msg) => a.deny(format!("{}/{}: {msg}", m.0, m.1)),
            Status::Patch(_) => unimplemented!(),
        }
    }
}

#[derive(Debug)]
pub enum DenyReason {
    InternalError(Report),
    IngressNoTLS,
    GatewayNoTLSListener,
    GatewayNonRedirectHTTPRouteAttachedToHTTPListener(
        Vec<(GatewayListeners, Parted<Vec<HTTPRoute>>)>,
    ),
    HTTPRouteNonRedirectAttachedToHTTPListener(Vec<(HTTPRouteParentRefs, GatewayListenerPair)>),
    CannotInferenceMutation,
}
impl Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let def_ns = "CLUSTERED".to_string();
        let empty_string = String::new();
        match self {
            Self::InternalError(report) => {
                f.write_str(&format!("Internal Error occurred.\n{report:?}"))
            }
            Self::IngressNoTLS => f.write_str("The Ingress does not contain a TLS configuration."),
            Self::GatewayNoTLSListener => {
                f.write_str("The Gateway does not contain a TLS configuration.")
            }
            Self::GatewayNonRedirectHTTPRouteAttachedToHTTPListener(listener_routes) => {
                let httproutes = listener_routes
                    .iter()
                    .map(|(_, v)| v)
                    .flat_map(|x| x.as_ref().bad)
                    .unique_by(|x| (x.metadata.name.as_ref(), x.metadata.namespace.as_ref()))
                    .collect::<Vec<_>>();
                f.write_str(&format!(
                "There are {} non-redirect HTTPRoutes (listed below) attaching to HTTP listeners of this Gateway.\n{}",
                httproutes.len(),
                httproutes.into_iter().map(|x| format!("{}/{}", x.metadata.namespace.as_ref().unwrap_or(&def_ns), x.metadata.name.as_ref().unwrap_or(&empty_string))).join("\n")
            ))
            }
            Self::HTTPRouteNonRedirectAttachedToHTTPListener(gateway_listeners) => {
                f.write_str(&format!(
                    "This non-redirect HTTPRoute is attaching to HTTP listeners of Gateways: {}",
                    gateway_listeners
                        .iter()
                        .map(|(_, x)| x.with_gateway(|g| format!(
                            "{}/{}",
                            g.metadata.namespace.as_ref().unwrap_or(&def_ns),
                            g.metadata.name.as_ref().unwrap_or(&empty_string)
                        )))
                        .join("\n")
                ))
            }
            Self::CannotInferenceMutation => {
                f.write_str("There is not enough information to make the mutation")
            }
        }
    }
}

pub trait ControlFlow {
    fn initialize_value() -> Self;
    fn is_continue(&self) -> bool;
    fn is_break(&self) -> bool {
        !self.is_continue()
    }
}

impl ControlFlow for Option<Result<Status>> {
    fn initialize_value() -> Self {
        Some(Ok(Status::MoveOn))
    }

    fn is_continue(&self) -> bool {
        matches!(self, Some(Ok(Status::MoveOn)) | None)
    }
}

pub type AsyncClosure<'a, I, O> = Box<dyn Fn(Arc<I>) -> BoxFuture<'a, O>>;
pub struct Checks<'a, I, O>(Vec<AsyncClosure<'a, I, O>>);
impl<I, O: ControlFlow> Checks<'_, I, O> {
    pub async fn run(&self, input: Arc<I>) -> O {
        let mut accum = O::initialize_value();
        for check in &self.0 {
            let x = input.clone();
            if accum.is_continue() {
                accum = check(x).await;
            } else if accum.is_break() {
                break;
            } else {
                unimplemented!()
            }
        }
        accum
    }
}
impl<'a, I, O> From<Vec<AsyncClosure<'a, I, O>>> for Checks<'a, I, O> {
    fn from(value: Vec<AsyncClosure<'a, I, O>>) -> Self {
        Self(value)
    }
}

pub trait HasMetadata {
    fn get_metadata(&self) -> &ObjectMeta;
}
impl HasMetadata for Ingress {
    fn get_metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}
impl HasMetadata for Gateway {
    fn get_metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}
impl HasMetadata for HTTPRoute {
    fn get_metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

pub fn get_skip(o: &impl HasMetadata) -> Option<&String> {
    let skip = o
        .get_metadata()
        .annotations
        .as_ref()?
        .get(SKIP_ANNOTATION)?;
    Some(skip)
}

pub fn get_external_dns_hostname(o: &impl HasMetadata) -> Option<Vec<String>> {
    o.get_metadata().annotations.as_ref().and_then(|a_s| {
        a_s.get("external-dns.alpha.kubernetes.io/hostname")
            .map(|s| {
                s.split(',')
                    // .filter(|x| !x.contains('*') && !x.starts_with('.'))
                    .map(|x| {
                        if x.starts_with('.') {
                            format!("*{x}")
                        } else {
                            x.to_string()
                        }
                    })
                    .collect()
            })
    })
}

#[instrument(skip_all)]
pub fn is_redirect_or_no_rule(httproute: &HTTPRoute) -> bool {
    let try_closure = || {
        httproute.spec.rules.as_ref().map_or(Some(true), |rules| {
            if rules.is_empty() {
                // another kind of no rules.
                Some(true)
            } else if rules.len() == 1
                && rules.first().is_some_and(|x| {
                    let y = HTTPRouteRules {
                        matches: Some(vec![HTTPRouteRulesMatches {
                            path: Some(HTTPRouteRulesMatchesPath {
                                r#type: Some(HTTPRouteRulesMatchesPathType::PathPrefix),
                                value: Some("/".to_string()),
                            }),
                            ..Default::default()
                        }]),
                        filters: Some(vec![HTTPRouteRulesFilters {
                            r#type: HTTPRouteRulesFiltersType::RequestRedirect,
                            request_redirect: Some(HTTPRouteRulesFiltersRequestRedirect {
                                scheme: Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
                                status_code: Some(302),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    };
                    x == &y
                })
            {
                // one and only redirect rule
                Some(true)
            } else {
                None
            }
        })
    };
    try_closure().unwrap_or_default()
}

pub fn does_parentref_listener_match(
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

#[derive(Debug)]
pub struct Parted<T> {
    pub good: T,
    pub bad: T,
}
impl<T> Parted<T> {
    pub const fn as_ref(&self) -> Parted<&T> {
        Parted {
            good: &self.good,
            bad: &self.bad,
        }
    }
}
