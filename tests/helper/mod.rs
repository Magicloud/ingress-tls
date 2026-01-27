use std::sync::OnceLock;

use eyre::Result;
use gateway_api::{gateways::Gateway, httproutes::HTTPRoute};
use k8s_openapi::{
    NamespaceResourceScope,
    api::{core::v1::Namespace, networking::v1::Ingress},
};
use kube::{
    Api, Client, Resource,
    api::{DeleteParams, ObjectMeta, PostParams},
};
use random_str::get_string;
use serde::{Serialize, de::DeserializeOwned};

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

pub static RUSTLS_FLAG: OnceLock<bool> = OnceLock::new();

pub fn get_test_namespace() -> String {
    std::env::var("TEST_NAMESPACE").unwrap_or("test".to_string())
}

pub async fn setup() -> Result<Client> {
    RUSTLS_FLAG.get_or_init(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Cannot initialize AWS LC");
        true
    });
    let client = Client::try_default().await?;
    let namespace = get_test_namespace();

    let namespaces: Api<Namespace> = Api::all(client.clone());
    if namespaces.get_opt(&namespace).await?.is_none() {
        let namespace = Namespace {
            metadata: ObjectMeta {
                name: Some(namespace.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        namespaces
            .create(&PostParams::default(), &namespace)
            .await?;
    }

    Ok(client)
}

pub fn run<T, U>(t: T, prep: Vec<U>) -> Result<()>
where
    T: HasMetadata
        + Resource<Scope = NamespaceResourceScope, DynamicType: Default>
        + Clone
        + std::fmt::Debug
        + Serialize
        + DeserializeOwned,
    U: HasMetadata
        + Resource<Scope = NamespaceResourceScope, DynamicType: Default>
        + Clone
        + std::fmt::Debug
        + Serialize
        + DeserializeOwned,
{
    let namespace = get_test_namespace();
    let ret: Result<()> = smol::block_on(async_compat::Compat::new(async {
        let client = setup().await?;
        for u in prep.iter() {
            let us: Api<U> = Api::namespaced(
                client.clone(),
                u.get_metadata().namespace.as_ref().unwrap_or(&namespace),
            );
            us.create(&PostParams::default(), u).await?;
            eprintln!(
                "Created {:?}/{:?}",
                u.get_metadata().namespace,
                u.get_metadata().name
            );
        }

        let ts: Api<T> = Api::namespaced(
            client.clone(),
            t.get_metadata().namespace.as_ref().unwrap_or(&namespace),
        );
        let x = ts.create(&PostParams::default(), &t).await;
        eprintln!(
            "Created {:?}/{:?}",
            t.get_metadata().namespace,
            t.get_metadata().name
        );
        let _ = ts
            .delete(
                t.get_metadata().name.as_ref().unwrap_or(&String::new()),
                &DeleteParams::default(),
            )
            .await;

        for u in prep {
            let us: Api<U> = Api::namespaced(
                client.clone(),
                u.get_metadata().namespace.as_ref().unwrap_or(&namespace),
            );
            let _ = us
                .delete(
                    u.get_metadata().name.as_ref().unwrap_or(&String::new()),
                    &DeleteParams::default(),
                )
                .await;
        }

        x?;
        Ok(())
    }));
    if let Err(e) = ret.as_ref() {
        eprintln!("{e:?}");
    }
    ret
}

pub fn gen_name(prefix: &str) -> String {
    format!(
        "ingress-tls-{prefix}-{}",
        get_string(7, true, false, false, false)
    )
}
