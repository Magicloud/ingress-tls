#![warn(clippy::cargo)]
#![warn(clippy::complexity)]
#![warn(clippy::correctness)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::perf)]
#![warn(clippy::style)]
#![warn(clippy::suspicious)]
#![allow(clippy::future_not_send)]
#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::wildcard_dependencies)]

mod cli;
mod gateway;
mod helpers;
mod httproute;
mod ingress;
mod tls_cert_resolver;
mod webhook;

use clap::Parser;
use eyre::Result;
use kube::{Client, api::GroupVersionKind};
use mimalloc::MiMalloc;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

#[allow(clippy::wildcard_imports)]
use crate::{cli::Cli, helpers::*};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// This usage seems breaking analyzer.
// #[macro_rules_attribute::apply(smol_macros::main!)]
fn main() -> Result<()> {
    smol::block_on(async_compat::Compat::new(real_main()))
}

async fn real_main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Cannot initialize AWS LC");
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer().with_span_events(FmtSpan::FULL))
        .with(tracing_error::ErrorLayer::default())
        .try_init()?;
    color_eyre::install()?;

    INGRESS_KIND
        .set(GroupVersionKind {
            group: "networking.k8s.io".to_owned(),
            version: "v1".to_owned(),
            kind: "Ingress".to_owned(),
        })
        .await
        .expect("Cannot init INGRESS_KIND");

    let gvks = ["v1", "v1alpha2", "v1alpha3", "v1beta1"]
        .into_iter()
        .map(|v| GroupVersionKind {
            group: "gateway.networking.k8s.io".to_owned(),
            version: v.to_owned(),
            kind: "Gateway".to_owned(),
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("Cannot convert vec to array as initing GATEWAY_KINDS");
    GATEWAY_KINDS
        .set(gvks)
        .await
        .expect("Cannot init GATEWAY_KINDS");

    let gvks = ["v1", "v1alpha2", "v1alpha3", "v1beta1"]
        .into_iter()
        .map(|v| GroupVersionKind {
            group: "gateway.networking.k8s.io".to_owned(),
            version: v.to_owned(),
            kind: "HTTPRoute".to_owned(),
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("Cannot convert vec to array as initing HTTPROUTE_KINDS");
    HTTPROUTE_KINDS
        .set(gvks)
        .await
        .expect("Cannot init HTTPROUTE_KINDS");

    let client = Client::try_default().await?;
    DEFAULT_NAMESPACE
        .set(client.default_namespace().to_string())
        .await
        .expect("Cannot init DEFAULT_NAMESPACE");

    let cli = Cli::parse();

    cli.start().await?;

    Ok(())
}
