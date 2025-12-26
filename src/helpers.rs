#![allow(dead_code)]

use std::{fmt::Display, str::FromStr};

use eyre::{Report, Result, eyre};
use gateway_api::{
    gateways::{Gateway, GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions},
    httproutes::HTTPRoute,
};
use just_string::JustString;
use k8s_openapi::api::{core::v1::Namespace, networking::v1::Ingress};
use kube::{
    Api, Client,
    api::{DynamicObject, GroupVersionKind, ListParams},
};
use mea::once::OnceCell;

pub static INGRESS_KIND: OnceCell<GroupVersionKind> = OnceCell::new();
pub static GATEWAY_KINDS: OnceCell<[GroupVersionKind; 4]> = OnceCell::new();
pub static HTTPROUTE_KINDS: OnceCell<[GroupVersionKind; 4]> = OnceCell::new();
pub static DEFAULT_NAMESPACE: OnceCell<String> = OnceCell::new();
pub static SKIP_VALIDATE_ANNOTATION: OnceCell<String> = OnceCell::new();
pub static SKIP_MUTATE_ANNOTATION: OnceCell<String> = OnceCell::new();

pub const TRAEFIK_MIDDLEWARE_ANNOTATION: JustString<'_> =
    JustString::RefStr("traefik.ingress.kubernetes.io/router.middlewares");
pub const NGINX_FORCE_SSL_REDIRECT: JustString<'_> =
    JustString::RefStr("nginx.ingress.kubernetes.io/force-ssl-redirect");
pub const ISSUER: JustString<'_> = JustString::RefStr("cert-manager.io/issuer");
pub const CLUSTER_ISSUER: JustString<'_> = JustString::RefStr("cert-manager.io/cluster-issuer");
pub const ISSUER_KIND: JustString<'_> = JustString::RefStr("cert-manager.io/issuer-kind");
pub const ISSUER_GROUP: JustString<'_> = JustString::RefStr("cert-manager.io/issuer-group");

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

// Maybe Result<Option<Gateway>>? kube client error and exist or not
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

pub trait AsyncResultExt<T, E> {
    async fn and_then_async<U, F, Fut>(self, f: F) -> Result<U, E>
    where
        F: FnOnce(T) -> Fut,
        Fut: Future<Output = Result<U, E>>;
}
impl<T, E> AsyncResultExt<T, E> for Result<T, E> {
    async fn and_then_async<U, F, Fut>(self, f: F) -> Result<U, E>
    where
        F: FnOnce(T) -> Fut,
        Fut: Future<Output = Result<U, E>>,
    {
        match self {
            Ok(value) => f(value).await,
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        // let x = rustls::crypto::aws_lc_rs::default_provider().install_default();
        // println!("{x:?}");
        let x = smol::block_on(async_compat::Compat::new(get_httproutes(&Namespaces::All)));
        println!("{x:?}");
    }
}
