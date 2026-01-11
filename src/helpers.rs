use std::{fmt::Display, str::FromStr};

use eyre::{Report, Result, eyre};
use futures::future::BoxFuture;
use gateway_api::{
    gateways::{
        Gateway, GatewayListeners, GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions,
    },
    httproutes::{
        HTTPRoute, HTTPRouteParentRefs, HTTPRouteRulesFiltersRequestRedirectScheme,
        HTTPRouteRulesFiltersType,
    },
};
use itertools::Itertools;
use json_patch::Patch;
use just_string::JustString;
use k8s_openapi::api::{core::v1::Namespace, networking::v1::Ingress};
use kube::{
    Api, Client,
    api::{DynamicObject, GroupVersionKind, ListParams, ObjectMeta},
};
use mea::once::OnceCell;
use serde::Serialize;
use tracing::instrument;

use crate::httproute::GatewayListenerPair;

pub static INGRESS_KIND: OnceCell<GroupVersionKind> = OnceCell::new();
pub static GATEWAY_KINDS: OnceCell<[GroupVersionKind; 4]> = OnceCell::new();
pub static HTTPROUTE_KINDS: OnceCell<[GroupVersionKind; 4]> = OnceCell::new();
pub const SKIP_ANNOTATION: &str = "ingress-tls.magiclouds.cn/skip";
pub const TRAEFIK_MIDDLEWARE_ANNOTATION: &str = "traefik.ingress.kubernetes.io/router.middlewares";
pub const NGINX_FORCE_SSL_REDIRECT: &str = "nginx.ingress.kubernetes.io/force-ssl-redirect";
pub const ISSUER: &str = "cert-manager.io/issuer";
pub const CLUSTER_ISSUER: &str = "cert-manager.io/cluster-issuer";
pub const ISSUER_KIND: &str = "cert-manager.io/issuer-kind";
pub const ISSUER_GROUP: &str = "cert-manager.io/issuer-group";

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

pub async fn filter_namespaces(selectors: &[SelectorByLabel]) -> Result<Vec<String>> {
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
    Some(Vec<JustString<'a>>),
}
#[allow(dead_code)]
pub enum SelectorByLabel {
    Is(String, String),
    IsNot(String, String),
    In(String, Vec<String>),
    NotIn(String, Vec<String>),
    Exists(String),
    DoesNotExist(String),
}
impl Display for SelectorByLabel {
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
impl From<(String, String)> for SelectorByLabel {
    fn from(value: (String, String)) -> Self {
        Self::Is(value.0, value.1)
    }
}
impl TryFrom<GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions> for SelectorByLabel {
    type Error = Report;

    fn try_from(
        value: GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions,
    ) -> std::result::Result<Self, Self::Error> {
        let ret = if value.operator == "In" {
            Self::In(
                value.key,
                value
                    .values
                    .ok_or_else(|| eyre!("`values` should be supplied in `In` operation"))?,
            )
        } else if value.operator == "NotIn" {
            Self::NotIn(
                value.key,
                value
                    .values
                    .ok_or_else(|| eyre!("`values` should be supplied in `NotIn` operation"))?,
            )
        } else if value.operator == "Exists" {
            Self::Exists(value.key)
        } else if value.operator == "DoesNotExist" {
            Self::DoesNotExist(value.key)
        } else {
            return Err(eyre!("Invalid operator {}", value.operator));
        };
        Ok(ret)
    }
}

// pub async fn any<I, Fut>(i: I) -> bool
// where
//     I: IntoIterator<Item = Fut>,
//     Fut: Future<Output = bool>,
// {
//     let mut futures: FuturesUnordered<_> = i.into_iter().collect();
//     while let Some(result) = futures.next().await {
//         if result {
//             return true;
//         }
//     }
//     return false;
// }

// pub trait AsyncResultExt<T, E> {
//     async fn and_then_async<U, F, Fut>(self, f: F) -> Result<U, E>
//     where
//         F: FnOnce(T) -> Fut,
//         Fut: Future<Output = Result<U, E>>;
// }
// impl<T, E> AsyncResultExt<T, E> for Result<T, E> {
//     async fn and_then_async<U, F, Fut>(self, f: F) -> Result<U, E>
//     where
//         F: FnOnce(T) -> Fut,
//         Fut: Future<Output = Result<U, E>>,
//     {
//         match self {
//             Ok(value) => f(value).await,
//             Err(e) => Err(e),
//         }
//     }
// }

pub trait OptionExt<T> {
    fn unwrap_ref(&self) -> &T;
}
impl<T> OptionExt<T> for Option<T> {
    fn unwrap_ref(&self) -> &T {
        self.as_ref().unwrap()
    }
}

pub trait ResultExt<T> {
    fn extract(self) -> T;
}
impl<T> ResultExt<T> for Result<T, T> {
    fn extract(self) -> T {
        match self {
            Ok(t) | Err(t) => t,
        }
    }
}

pub fn patch<T: Serialize>(src: &T, dst: &T) -> Result<Patch> {
    let s = serde_json::to_value(src)?;
    let d = serde_json::to_value(dst)?;
    let p = json_patch::diff(&s, &d);
    Ok(p)
}

pub enum Status {
    MoveOn,
    Allowed,
    Denied(DenyReason),
    Invalid(String),
    Patch(Patch),
}

pub enum DenyReason {
    InternalError(Report),
    IngressNoTLS,
    GatewayNoTLSListener,
    GatewayNonRedirectHTTPRouteAttachedToHTTPListener(
        Vec<(GatewayListeners, Parted<Vec<HTTPRoute>>)>,
    ),
    HTTPRouteNonRedirectAttachedToHTTPListener(Vec<(HTTPRouteParentRefs, GatewayListenerPair)>),
}
impl Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // let def_ns = DEFAULT_NAMESPACE
        //     .get()
        //     .expect("Cannot get DEFAULT_NAMESPACE");
        let def_ns = "CLUSTERED".to_string();
        let empty_string = String::new();
        match self {
            Self::InternalError(report) => {
                f.write_str(&format!("Internal Error occurred.\n{report:?}"))
            }
            Self::IngressNoTLS => f.write_str("The Ingress does not contain a TLS configuration."),
            Self::GatewayNoTLSListener => {
                f.write_str("The Gateway doe s not contain a TLS configuration.")
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
        }
    }
}

pub type AsyncClosure<'a, T> = Box<dyn Fn(T) -> BoxFuture<'a, Result<Status>>>;

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

pub trait VecExt<T> {
    // fn push_return(self, value: T) -> Self;
    // fn append_return(self, other: &mut Vec<T>) -> Self;
    fn extend_return(self, iter: impl IntoIterator<Item = T>) -> Self;
}
impl<T> VecExt<T> for Vec<T> {
    // fn push_return(mut self, value: T) -> Self {
    //     self.push(value);
    //     self
    // }
    // fn append_return(mut self, other: &mut Self) -> Self {
    //     self.append(other);
    //     self
    // }
    fn extend_return(mut self, iter: impl IntoIterator<Item = T>) -> Self {
        self.extend(iter);
        self
    }
}

#[instrument]
pub fn is_redirect_or_no_rule(httproute: &HTTPRoute) -> bool {
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
        false
    }
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
