use std::path::PathBuf;
use std::str::FromStr;

use clap::{
    ArgAction, Parser,
    builder::{StringValueParser, TypedValueParser},
};
use eyre::eyre;

#[derive(Parser, Clone, Debug)]
pub struct Cli {
    /// Webhook service listening address
    /// In format `HOST:PORT`
    #[arg(short, long, default_value = "0.0.0.0:443",
        value_parser = StringValueParser::new().try_map(|s| {
            s.split_once(':').ok_or(eyre!("Invalid format of annotation"))
            .and_then(|(a, b)| u16::from_str(b).map(|b|(a.to_owned(), b))
            .map_err(|e| eyre!("{e:?}")))
        }))]
    pub listen_address: (String, u16),
    /// Annotation to be added to the Ingress
    /// In format `NAME:VALUE`
    #[arg(short('a'), long, action = ArgAction::Append,
        value_parser = StringValueParser::new().try_map(|s| {
            s.split_once(':').map(|(a, b)| (a.to_owned(), b.to_owned()))
            .ok_or(eyre!("Invalid format of annotation"))
        }))]
    pub cert_manager_annotations: Vec<(String, String)>,
    /// Traefik Ingress middleware to redirect HTTP to HTTPS
    /// In format `NAME`. `NAMESPACE/NAME` if the Middleware is not in the same
    /// namespace with Ingress.
    #[arg(short, long)]
    pub traefik_ingress_redirect_resource_name: Option<String>,
    /// Webhook service TLS certificate file path
    #[arg(short('c'), long)]
    pub tls_certificate_file_path: PathBuf,
    /// Webhook service TLS private key file path
    #[arg(short('k'), long)]
    pub tls_private_key_file_path: PathBuf,
}
