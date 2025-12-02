use std::sync::Arc;

use actix_web::{
    App, HttpServer,
    guard::GuardContext,
    http::header::ContentType,
    middleware::Logger,
    post,
    web::{Data, Json},
};
use eyre::{Result, eyre};
use kube::{
    api::DynamicObject,
    core::admission::{AdmissionResponse, AdmissionReview},
};
use rustls::ServerConfig;
use serde_json::Value;

use crate::{
    admission_control::{mutate_ingress, validate_ingress},
    cli::Cli,
    tls_cert_resolver::TLSCertResolver,
};

impl Cli {
    pub async fn start(self) -> Result<()> {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .map_err(|_| eyre!("Cannot initialize AWS LC"))?;
        let cert_solver = TLSCertResolver::new(
            &self.tls_certificate_file_path,
            &self.tls_private_key_file_path,
            rustls::crypto::CryptoProvider::get_default().expect("Provider did not initialize"),
        )?;

        let addr = self.listen_address.clone();

        let data = Arc::new(self);
        HttpServer::new(move || {
            App::new()
                .wrap(Logger::default())
                .app_data(Data::new(data.clone()))
                .service(post_ingress_validate)
                .service(post_ingress_mutate)
        })
        .workers(2)
        // Adminssion Control webhooks are required to be secured.
        // The services are accessed from within the cluster directly,
        // so we cannot depend on Ingress to implement the TLS.
        .bind_rustls_0_23(
            addr,
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(cert_solver)),
        )?
        .run()
        .await?;
        Ok(())
    }
}

fn json_guard(ctx: &GuardContext<'_>) -> bool {
    ctx.header::<ContentType>()
        .is_some_and(|ct| ContentType::json() == ct)
}

#[post("/ingress/validate", guard = "json_guard")]
async fn post_ingress_validate(
    admission_review: Json<Value>,
) -> Json<AdmissionReview<DynamicObject>> {
    let json = admission_review.into_inner();
    let ret = match serde_json::from_value::<AdmissionReview<DynamicObject>>(json) {
        Ok(ar) => {
            // One may use `ar.request` according to doc. But that is wrong. `try_into` is the proper way.
            // `request` returns a broken `AdmissionRequest`, such as no api version and kind data.
            ar.try_into().as_ref().map_or_else(
                |_| AdmissionResponse::invalid("No request got"),
                validate_ingress,
            )
        }
        Err(e) => AdmissionResponse::invalid(format!("{e:?}")),
    };
    Json(ret.into_review())
}

#[post("/ingress/mutate", guard = "json_guard")]
async fn post_ingress_mutate(
    admission_review: Json<Value>,
    conf: Data<Arc<Cli>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let json = admission_review.into_inner();
    let ret = match serde_json::from_value::<AdmissionReview<DynamicObject>>(json) {
        Ok(ar) => match ar.try_into() {
            Ok(req) => mutate_ingress(&req, conf.get_ref()).await,
            Err(e) => {
                tracing::error!("{e:?}");
                AdmissionResponse::invalid("No request got")
            }
        },
        Err(e) => AdmissionResponse::invalid(format!("{e:?}")),
    };
    Json(ret.into_review())
}
