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
use opentelemetry::trace::TracerProvider;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::{Resource, logs::SdkLoggerProvider, trace::SdkTracerProvider};
use tracing::{level_filters::LevelFilter, warn};
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    EnvFilter, Layer,
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

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

    let log_provider = match opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .build()
    {
        Ok(log_exporter) => SdkLoggerProvider::builder()
            .with_resource(Resource::builder().with_service_name("ingress-tls").build())
            .with_batch_exporter(log_exporter)
            .build(),
        Err(e) => {
            eprintln!("Cannot initialize OTLP log exporter: {e:?}");
            SdkLoggerProvider::builder()
                .with_batch_exporter(opentelemetry_stdout::LogExporter::default())
                .build()
        }
    };

    let trace_provider = match opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
    {
        Ok(trace_exporter) => Some(
            SdkTracerProvider::builder()
                .with_resource(Resource::builder().with_service_name("ingress-tls").build())
                .with_batch_exporter(trace_exporter)
                .build()
                .tracer("ingress-tls"),
        ),
        Err(e) => {
            warn!(target: "OTLP", message = format!("Failed to initialize trace exporter: {e:?}"));
            None
        }
    };

    let r = tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_span_events(FmtSpan::NONE)
                .with_filter(EnvFilter::from_default_env()),
        )
        .with(ErrorLayer::default())
        .with(OpenTelemetryTracingBridge::new(&log_provider).with_filter(LevelFilter::INFO));
    if let Some(tp) = trace_provider {
        r.with(
            tracing_opentelemetry::layer()
                .with_tracer(tp)
                .with_filter(LevelFilter::INFO),
        )
        .try_init()?;
    } else {
        r.try_init()?;
    }

    color_eyre::install()?;

    let cli = Cli::parse();
    cli.start().await?;

    Ok(())
}
