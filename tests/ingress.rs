mod helper;

use std::collections::BTreeMap;

use k8s_openapi::api::networking::v1::{
    HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule,
    IngressServiceBackend, IngressSpec, IngressTLS, ServiceBackendPort,
};
use kube::api::ObjectMeta;

use crate::helper::*;

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
            name: Some(gen_name("good")),
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
    assert!(run(good_ingress, vec![] as Vec<Ingress>).is_ok());
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
            name: Some(gen_name("no-tls")),
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
    assert!(run(no_tls_ingress, vec![] as Vec<Ingress>).is_err())
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
            name: Some(gen_name("skip")),
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
    assert!(run(skip_ingress, vec![] as Vec<Ingress>).is_ok())
}
