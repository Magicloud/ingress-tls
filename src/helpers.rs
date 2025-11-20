use std::fmt::Display;

use eyre::Result;
use k8s_openapi::api::networking::v1::Ingress;
use kube::api::{DynamicObject, GroupVersionKind};
use logcall::logcall;
use serde::Serialize;
use smol::lock::OnceCell;

pub static INGRESS_KIND: OnceCell<GroupVersionKind> = OnceCell::new();

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
