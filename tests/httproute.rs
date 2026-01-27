mod helper;

use std::collections::BTreeMap;

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
use kube::api::ObjectMeta;

use crate::helper::*;

#[test]
fn good_httproute() {
    let prep = Gateway {
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
            name: Some(gen_name("good")),
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
    let good_httproute = HTTPRoute {
        metadata: ObjectMeta {
            name: Some(gen_name("good-http")),
            ..Default::default()
        },
        spec: HTTPRouteSpec {
            parent_refs: Some(vec![HTTPRouteParentRefs {
                kind: Some("Gateway".to_string()),
                name: prep.metadata.name.clone().unwrap(),
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
    };

    assert!(run(good_httproute, vec![prep]).is_ok());
}

#[test]
fn skip_httproute() {
    let prep = Gateway {
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
            name: Some(gen_name("bad-httproute")),
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
    let skip_httproute = HTTPRoute {
        metadata: ObjectMeta {
            name: Some(gen_name("bad-http")),
            annotations: Some(BTreeMap::from_iter(
                [("ingress-tls.magiclouds.cn/skip", "true")]
                    .into_iter()
                    .map(|(x, y)| (x.to_string(), y.to_string())),
            )),
            ..Default::default()
        },
        spec: HTTPRouteSpec {
            parent_refs: Some(vec![HTTPRouteParentRefs {
                kind: Some("Gateway".to_string()),
                name: prep.metadata.name.clone().unwrap(),
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
    };

    assert!(run(skip_httproute, vec![prep]).is_ok());
}

#[test]
fn bad_httproute() {
    let prep = Gateway {
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
            name: Some(gen_name("bad-httproute")),
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
    let bad_httproute = HTTPRoute {
        metadata: ObjectMeta {
            name: Some(gen_name("bad-http")),
            ..Default::default()
        },
        spec: HTTPRouteSpec {
            parent_refs: Some(vec![HTTPRouteParentRefs {
                kind: Some("Gateway".to_string()),
                name: prep.metadata.name.clone().unwrap(),
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
    };

    assert!(run(bad_httproute, vec![prep]).is_err());
}
