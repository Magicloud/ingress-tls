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

mod admission_control;
mod cli;
mod helpers;
mod tls_cert_resolver;
mod webhook;

use clap::Parser;
use eyre::Result;
use kube::api::GroupVersionKind;
use mimalloc::MiMalloc;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{cli::Cli, helpers::INGRESS_KIND};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// This usage seems breaking analyzer.
// #[macro_rules_attribute::apply(smol_macros::main!)]
fn main() -> Result<()> {
    smol::block_on(async_compat::Compat::new(real_main()))
}

async fn real_main() -> Result<()> {
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

    let cli = Cli::parse();

    cli.start().await?;

    Ok(())
}
