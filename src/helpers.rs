use std::str::FromStr;

use eyre::{Result, eyre};
use just_string::JustString;
use k8s_openapi::api::networking::v1::Ingress;
use kube::api::{DynamicObject, GroupVersionKind};
use logcall::logcall;
use smol::lock::OnceCell;

pub static INGRESS_KIND: OnceCell<GroupVersionKind> = OnceCell::new();
pub const TRAEFIK_MIDDLEWARE_ANNOTATION: JustString<'_> =
    JustString::RefStr("traefik.ingress.kubernetes.io/router.middlewares");
pub const NGINX_FORCE_SSL_REDIRECT: JustString<'_> =
    JustString::RefStr("nginx.ingress.kubernetes.io/force-ssl-redirect");
pub const ISSUER: JustString<'_> = JustString::RefStr("cert-manager.io/issuer");
pub const CLUSTER_ISSUER: JustString<'_> = JustString::RefStr("cert-manager.io/cluster-issuer");
pub const ISSUER_KIND: JustString<'_> = JustString::RefStr("cert-manager.io/issuer-kind");
pub const ISSUER_GROUP: JustString<'_> = JustString::RefStr("cert-manager.io/issuer-group");

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
