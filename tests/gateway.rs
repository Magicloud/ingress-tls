use std::{collections::BTreeMap, sync::OnceLock};

use eyre::Result;
use gateway_api::{
    gateways::{
        Gateway, GatewayListeners, GatewayListenersTls, GatewayListenersTlsCertificateRefs,
        GatewayListenersTlsMode, GatewaySpec,
    },
    httproutes::{
        HTTPRoute, HTTPRouteParentRefs, HTTPRouteRules, HTTPRouteRulesBackendRefs,
        HTTPRouteRulesFilters, HTTPRouteRulesFiltersRequestRedirect,
        HTTPRouteRulesFiltersRequestRedirectScheme, HTTPRouteRulesFiltersType,
        HTTPRouteRulesMatches, HTTPRouteRulesMatchesPath, HTTPRouteRulesMatchesPathType,
        HTTPRouteSpec,
    },
};
use k8s_openapi::{NamespaceResourceScope, api::core::v1::Namespace};
use kube::{
    Api, Client, Resource,
    api::{DeleteParams, ObjectMeta, PostParams},
};
use serde::{Serialize, de::DeserializeOwned};

pub trait HasMetadata {
    fn get_metadata(&self) -> &ObjectMeta;
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

static RUSTLS_FLAG: OnceLock<bool> = OnceLock::new();

fn get_test_namespace() -> String {
    std::env::var("TEST_NAMESPACE").unwrap_or("test".to_string())
}

fn setup() -> Result<Client> {
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

        Ok(client)
    }))
}

fn run<T, U>(t: T, prep: Vec<U>) -> Result<()>
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
    let client = setup()?;
    let namespace = get_test_namespace();
    let ret: Result<()> = smol::block_on(async_compat::Compat::new(async {
        for u in prep.iter() {
            let us: Api<U> = Api::namespaced(
                client.clone(),
                u.get_metadata().namespace.as_ref().unwrap_or(&namespace),
            );
            us.create(&PostParams::default(), u).await?;
        }

        let ts: Api<T> = Api::namespaced(
            client.clone(),
            t.get_metadata().namespace.as_ref().unwrap_or(&namespace),
        );
        let x = ts.create(&PostParams::default(), &t).await;
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

#[test]
fn good_gateway() {
    let good_gateway = Gateway {
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
            name: Some("good-gateway".to_string()),
            ..Default::default()
        },
        spec: GatewaySpec {
            gateway_class_name: "traefik".to_string(),
            listeners: vec![
                GatewayListeners {
                    name: "http".to_string(),
                    port: 8000,
                    protocol: "HTTP".to_string(),
                    ..Default::default()
                },
                GatewayListeners {
                    name: "https".to_string(),
                    port: 8443,
                    protocol: "HTTPS".to_string(),
                    hostname: Some("whoami.magicloud.lan".to_string()),
                    tls: Some(GatewayListenersTls {
                        certificate_refs: Some(vec![GatewayListenersTlsCertificateRefs {
                            name: "good-gateway".to_string(),
                            ..Default::default()
                        }]),
                        mode: Some(GatewayListenersTlsMode::Terminate),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        ..Default::default()
    };
    let prep = vec![
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some("good-http-httproute-good-gateway".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: Some(vec![HTTPRouteParentRefs {
                    kind: Some("Gateway".to_string()),
                    name: "good-gateway".to_string(),
                    section_name: Some("http".to_string()),
                    ..Default::default()
                }]),
                rules: Some(vec![HTTPRouteRules {
                    filters: Some(vec![HTTPRouteRulesFilters {
                        request_redirect: Some(HTTPRouteRulesFiltersRequestRedirect {
                            scheme: Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
                            ..Default::default()
                        }),
                        r#type: HTTPRouteRulesFiltersType::RequestRedirect,
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        },
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some("outside-bad-http-httproute-good-gateway".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: Some(vec![HTTPRouteParentRefs {
                    kind: Some("Gateway".to_string()),
                    name: "good-gateway".to_string(),
                    section_name: Some("http".to_string()),
                    ..Default::default()
                }]),
                rules: Some(vec![HTTPRouteRules {
                    matches: Some(vec![HTTPRouteRulesMatches {
                        path: Some(HTTPRouteRulesMatchesPath {
                            r#type: Some(HTTPRouteRulesMatchesPathType::PathPrefix),
                            value: Some("/".to_string()),
                        }),
                        ..Default::default()
                    }]),
                    backend_refs: Some(vec![HTTPRouteRulesBackendRefs {
                        name: "test".to_string(),
                        namespace: Some("test".to_string()),
                        port: Some(88),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        },
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some("good-https-httproute-good-gateway".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: Some(vec![HTTPRouteParentRefs {
                    kind: Some("Gateway".to_string()),
                    name: "good-gateway".to_string(),
                    section_name: Some("https".to_string()),
                    ..Default::default()
                }]),
                rules: Some(vec![HTTPRouteRules {
                    matches: Some(vec![HTTPRouteRulesMatches {
                        path: Some(HTTPRouteRulesMatchesPath {
                            r#type: Some(HTTPRouteRulesMatchesPathType::PathPrefix),
                            value: Some("/".to_string()),
                        }),
                        ..Default::default()
                    }]),
                    backend_refs: Some(vec![HTTPRouteRulesBackendRefs {
                        name: "test".to_string(),
                        namespace: Some("test".to_string()),
                        port: Some(88),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        },
    ];

    assert!(run(good_gateway, prep).is_ok());
}

#[test]
fn skip_gateway() {
    let skip_gateway = Gateway {
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
            name: Some("good-gateway".to_string()),
            ..Default::default()
        },
        spec: GatewaySpec {
            gateway_class_name: "traefik".to_string(),
            listeners: vec![GatewayListeners {
                name: "http".to_string(),
                port: 8000,
                protocol: "HTTP".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(run(skip_gateway, vec![] as Vec<HTTPRoute>).is_ok());
}

#[test]
fn no_tls_gateway() {
    let no_tls_gateway = Gateway {
        metadata: ObjectMeta {
            annotations: Some(BTreeMap::from_iter(
                [(
                    "external-dns.alpha.kubernetes.io/hostname",
                    "whoami.magicloud.lan.",
                )]
                .into_iter()
                .map(|(x, y)| (x.to_string(), y.to_string())),
            )),
            name: Some("good-gateway".to_string()),
            ..Default::default()
        },
        spec: GatewaySpec {
            gateway_class_name: "traefik".to_string(),
            listeners: vec![GatewayListeners {
                name: "http".to_string(),
                port: 8000,
                protocol: "HTTP".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(run(no_tls_gateway, vec![] as Vec<HTTPRoute>).is_err())
}

#[test]
fn bad_httproute_gateway() {
    let bad_httproute_gateway = Gateway {
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
            name: Some("bad-httproute-gateway".to_string()),
            ..Default::default()
        },
        spec: GatewaySpec {
            gateway_class_name: "traefik".to_string(),
            listeners: vec![
                GatewayListeners {
                    name: "http".to_string(),
                    port: 8000,
                    protocol: "HTTP".to_string(),
                    ..Default::default()
                },
                GatewayListeners {
                    name: "https".to_string(),
                    port: 8443,
                    protocol: "HTTPS".to_string(),
                    hostname: Some("whoami.magicloud.lan".to_string()),
                    tls: Some(GatewayListenersTls {
                        certificate_refs: Some(vec![GatewayListenersTlsCertificateRefs {
                            name: "good-gateway".to_string(),
                            ..Default::default()
                        }]),
                        mode: Some(GatewayListenersTlsMode::Terminate),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        ..Default::default()
    };
    let prep = vec![
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some("good-http-httproute-bad-httproute-gateway".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: Some(vec![HTTPRouteParentRefs {
                    kind: Some("Gateway".to_string()),
                    name: "bad-httproute-gateway".to_string(),
                    section_name: Some("http".to_string()),
                    ..Default::default()
                }]),
                rules: Some(vec![HTTPRouteRules {
                    filters: Some(vec![HTTPRouteRulesFilters {
                        request_redirect: Some(HTTPRouteRulesFiltersRequestRedirect {
                            scheme: Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
                            ..Default::default()
                        }),
                        r#type: HTTPRouteRulesFiltersType::RequestRedirect,
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        },
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some("bad-http-httproute-bad-httproute-gateway".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: Some(vec![HTTPRouteParentRefs {
                    kind: Some("Gateway".to_string()),
                    name: "bad-httproute-gateway".to_string(),
                    section_name: Some("http".to_string()),
                    ..Default::default()
                }]),
                rules: Some(vec![HTTPRouteRules {
                    matches: Some(vec![HTTPRouteRulesMatches {
                        path: Some(HTTPRouteRulesMatchesPath {
                            r#type: Some(HTTPRouteRulesMatchesPathType::PathPrefix),
                            value: Some("/".to_string()),
                        }),
                        ..Default::default()
                    }]),
                    backend_refs: Some(vec![HTTPRouteRulesBackendRefs {
                        name: "test".to_string(),
                        namespace: Some("test".to_string()),
                        port: Some(88),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        },
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some("good-https-httproute-bad-httproute-gateway".to_string()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                parent_refs: Some(vec![HTTPRouteParentRefs {
                    kind: Some("Gateway".to_string()),
                    name: "bad-httproute-gateway".to_string(),
                    section_name: Some("https".to_string()),
                    ..Default::default()
                }]),
                rules: Some(vec![HTTPRouteRules {
                    matches: Some(vec![HTTPRouteRulesMatches {
                        path: Some(HTTPRouteRulesMatchesPath {
                            r#type: Some(HTTPRouteRulesMatchesPathType::PathPrefix),
                            value: Some("/".to_string()),
                        }),
                        ..Default::default()
                    }]),
                    backend_refs: Some(vec![HTTPRouteRulesBackendRefs {
                        name: "test".to_string(),
                        namespace: Some("test".to_string()),
                        port: Some(88),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        },
    ];

    assert!(run(bad_httproute_gateway, prep).is_err());
}
