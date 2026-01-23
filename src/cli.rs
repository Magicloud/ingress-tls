use std::path::PathBuf;
use std::str::FromStr;

use clap::{
    Args, Parser,
    builder::{StringValueParser, TypedValueParser},
};
use eyre::eyre;

use crate::helpers::Issuer;

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
    /// Cert Manager annotation to be added to the Ingress
    /// In format `NAME:VALUE`
    /// Required by mutating webhook.
    #[command(flatten)]
    pub cma: Option<CertManagerAnnotations>,
    /// Traefik Ingress middleware to redirect HTTP to HTTPS
    /// In format `NAME`. `NAMESPACE/NAME` if the Middleware is not in the same
    /// namespace with Ingress.
    #[arg(short, long)]
    pub traefik_ingress_redirect_resource_name: Option<String>,
    /// Webhook service TLS certificate files folder
    #[arg(short('f'), long)]
    pub tls_folder: PathBuf,
    /// Webhook service TLS certificate file path
    #[arg(short('c'), long)]
    pub tls_certificate_file_name: String,
    /// Webhook service TLS private key file path
    #[arg(short('k'), long)]
    pub tls_private_key_file_name: String,
}

#[derive(Debug, Clone, Args)]
pub struct CertManagerAnnotations {
    #[arg(long, value_parser = StringValueParser::new().try_map(|s| {
            s.split_once(':').ok_or(eyre!("Invalid format of annotation"))
            .and_then(|(a, b)| if a.to_lowercase() == "namespaced" {
                Ok(Issuer::Namespaced(b.to_owned()))
            }else if a.to_lowercase() == "clustered" {
                Ok(Issuer::Clustered(b.to_owned()))
            } else {
                Err(eyre!("Invalid issuer type"))
            })
        }))]
    pub issuer: Issuer,
    #[arg(long)]
    pub kind: Option<String>,
    #[arg(long)]
    pub group: Option<String>,
}
