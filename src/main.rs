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
use mimalloc::MiMalloc;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

#[allow(clippy::wildcard_imports)]
use crate::cli::Cli;

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
        .with(tracing_subscriber::fmt::layer().with_span_events(FmtSpan::NONE))
        .with(tracing_error::ErrorLayer::default())
        .try_init()?;
    color_eyre::install()?;

    let cli = Cli::parse();

    cli.start().await?;

    Ok(())
}
