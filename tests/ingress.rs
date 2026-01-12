use std::{collections::BTreeMap, sync::OnceLock};

use eyre::Result;
use k8s_openapi::api::{
    core::v1::Namespace,
    networking::v1::{
        HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule,
        IngressServiceBackend, IngressSpec, IngressTLS, ServiceBackendPort,
    },
};
use kube::{
    Api, Client,
    api::{DeleteParams, ObjectMeta, PostParams},
};

static RUSTLS_FLAG: OnceLock<bool> = OnceLock::new();

fn get_test_namespace() -> String {
    std::env::var("TEST_NAMESPACE").unwrap_or("test".to_string())
}

fn setup() -> Result<Api<Ingress>> {
    RUSTLS_FLAG.get_or_init(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Cannot initialize AWS LC");
        true
    });
    smol::block_on(async_compat::Compat::new(async {
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

        let ingresses: Api<Ingress> = Api::namespaced(client, &namespace);

        Ok(ingresses) as Result<_>
    }))
}

fn run(ingress: Ingress) -> Result<()> {
    let ingresses = setup()?;
    let ret: Result<()> = smol::block_on(async_compat::Compat::new(async {
        let x = ingresses.create(&PostParams::default(), &ingress).await;
        let _ = ingresses
            .delete(
                &ingress.metadata.name.unwrap_or_default(),
                &DeleteParams::default(),
            )
            .await;
        x?;
        Ok(())
    }));
    if let Err(e) = ret.as_ref() {
        eprintln!("{e:?}");
    }
    ret
}

#[test]
fn good_ingress() {
    let good_ingress = Ingress {
        metadata: ObjectMeta {
            annotations: Some(BTreeMap::from_iter(
                [
                    (
                        "external-dns.alpha.kubernetes.io/hostname",
                        "whoami.magicloud.lan.",
                    ),
                    ("cert-manager.io/issuer", "step-issuer"),
                    ("cert-manager.io/issuer-kind", "StepClusterIssuer"),
                    ("cert-manager.io/issuer-group", "certmanager.step.sm"),
                ]
                .into_iter()
                .map(|(x, y)| (x.to_string(), y.to_string())),
            )),
            name: Some("good-ingress".to_string()),
            ..ObjectMeta::default()
        },
        spec: Some(IngressSpec {
            rules: Some(vec![IngressRule {
                host: Some("whoami.magicloud.lan".to_string()),
                http: Some(HTTPIngressRuleValue {
                    paths: vec![HTTPIngressPath {
                        backend: IngressBackend {
                            resource: None,
                            service: Some(IngressServiceBackend {
                                name: "whoami".to_string(),
                                port: Some(ServiceBackendPort {
                                    name: None,
                                    number: Some(80),
                                }),
                            }),
                        },
                        path: Some("/".to_string()),
                        path_type: "Prefix".to_string(),
                    }],
                }),
            }]),
            tls: Some(vec![IngressTLS {
                hosts: Some(vec!["whoami.magicloud.lan".to_string()]),
                secret_name: Some("good-ingress-tls".to_string()),
            }]),
            ..IngressSpec::default()
        }),
        status: None,
    };
    assert!(run(good_ingress).is_ok());
}

#[test]
fn no_tls_ingress() {
    let no_tls_ingress = Ingress {
        metadata: ObjectMeta {
            annotations: Some(BTreeMap::from_iter(
                [(
                    "external-dns.alpha.kubernetes.io/hostname",
                    "whoami.magicloud.lan.",
                )]
                .into_iter()
                .map(|(x, y)| (x.to_string(), y.to_string())),
            )),
            name: Some("no-tls-ingress".to_string()),
            ..ObjectMeta::default()
        },
        spec: Some(IngressSpec {
            rules: Some(vec![IngressRule {
                host: Some("whoami.magicloud.lan".to_string()),
                http: Some(HTTPIngressRuleValue {
                    paths: vec![HTTPIngressPath {
                        backend: IngressBackend {
                            resource: None,
                            service: Some(IngressServiceBackend {
                                name: "whoami".to_string(),
                                port: Some(ServiceBackendPort {
                                    name: None,
                                    number: Some(80),
                                }),
                            }),
                        },
                        path: Some("/".to_string()),
                        path_type: "Prefix".to_string(),
                    }],
                }),
            }]),
            tls: None,
            ..IngressSpec::default()
        }),
        status: None,
    };
    assert!(run(no_tls_ingress).is_err())
}

#[test]
fn skip_ingress() {
    let skip_ingress = Ingress {
        metadata: ObjectMeta {
            annotations: Some(BTreeMap::from_iter(
                [
                    (
                        "external-dns.alpha.kubernetes.io/hostname",
                        "whoami.magicloud.lan.",
                    ),
                    ("ingress-tls.magiclouds.cn/skip", "true"),
                ]
                .into_iter()
                .map(|(x, y)| (x.to_string(), y.to_string())),
            )),
            name: Some("no-tls-ingress".to_string()),
            ..ObjectMeta::default()
        },
        spec: Some(IngressSpec {
            rules: Some(vec![IngressRule {
                host: Some("whoami.magicloud.lan".to_string()),
                http: Some(HTTPIngressRuleValue {
                    paths: vec![HTTPIngressPath {
                        backend: IngressBackend {
                            resource: None,
                            service: Some(IngressServiceBackend {
                                name: "whoami".to_string(),
                                port: Some(ServiceBackendPort {
                                    name: None,
                                    number: Some(80),
                                }),
                            }),
                        },
                        path: Some("/".to_string()),
                        path_type: "Prefix".to_string(),
                    }],
                }),
            }]),
            tls: None,
            ..IngressSpec::default()
        }),
        status: None,
    };
    assert!(run(skip_ingress).is_ok())
}
