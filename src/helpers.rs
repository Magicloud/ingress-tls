use std::{fmt::Display, str::FromStr};

use eyre::{Result, eyre};
use k8s_openapi::api::networking::v1::{Ingress, IngressClass};
use kube::{
    Api, Client,
    api::{DynamicObject, GroupVersionKind, ListParams},
};
use logcall::logcall;
use serde::Serialize;
use smol::lock::OnceCell;

pub static INGRESS_KIND: OnceCell<GroupVersionKind> = OnceCell::new();
pub static TRAEFIK_MIDDLEWARE_ANNOTATION: &str = "traefik.ingress.kubernetes.io/router.middlewares";
pub static NGINX_FORCE_SSL_REDIRECT: &str = "nginx.ingress.kubernetes.io/force-ssl-redirect";
pub static IS_DEFAULT_CLASS: &str = " nginx.ingress.kubernetes.io/force-ssl-redirect";

// Why this is not a Trait for all objects.
#[logcall(err = "Warn")]
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

#[derive(Serialize)]
#[serde(untagged)]
pub enum Either<A, B> {
    A(A),
    B(B),
}
impl<A: Display, B: Display> Display for Either<A, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A(a) => a.fmt(f),
            Self::B(b) => b.fmt(f),
        }
    }
}
impl PartialEq for Either<&String, &str> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::A(l0), Self::A(r0)) => l0 == r0,
            (Self::B(l0), Self::B(r0)) => l0 == r0,
            (Self::A(a), Self::B(b)) => a.as_str() == *b,
            (Self::B(b), Self::A(a)) => *b == a.as_str(),
        }
    }
}
impl PartialOrd for Either<&String, &str> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Eq for Either<&String, &str> {}
impl Ord for Either<&String, &str> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::A(a), Self::A(a_)) => a.cmp(a_),
            (Self::A(a), Self::B(b)) => a.as_str().cmp(b),
            (Self::B(b), Self::A(a)) => b.cmp(&a.as_str()),
            (Self::B(b), Self::B(b_)) => b.cmp(b_),
        }
    }
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

#[logcall]
pub async fn get_default_ingressclass() -> Result<Option<String>> {
    let client = Client::try_default().await?;
    let ingress_classes: Api<IngressClass> = Api::all(client);
    let lp = ListParams::default();
    let false_str = "false".to_owned();
    let default_ingressclass_name = ingress_classes.list(&lp).await?.iter().find_map(|ic| {
        let is_default_class = ic
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(IS_DEFAULT_CLASS))
            .unwrap_or(&false_str);
        if is_default_class == "true" {
            ic.metadata.name.clone()
        } else {
            None
        }
    });
    Ok(default_ingressclass_name)
}
