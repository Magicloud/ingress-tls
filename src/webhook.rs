use std::sync::Arc;

use actix_web::{
    App, HttpServer,
    guard::GuardContext,
    http::header::ContentType,
    middleware::Logger,
    post,
    web::{Data, Json},
};
use eyre::Result;
use kube::{
    api::DynamicObject,
    core::admission::{AdmissionResponse, AdmissionReview},
};
use rustls::ServerConfig;
use serde_json::Value;

#[allow(clippy::wildcard_imports)]
use crate::{admission_control::*, cli::Cli, helpers::*, tls_cert_resolver::TLSCertResolver};

impl Cli {
    pub async fn start(self) -> Result<()> {
        let cert_solver = TLSCertResolver::new(
            &self.tls_certificate_file_path,
            &self.tls_private_key_file_path,
            rustls::crypto::CryptoProvider::get_default().expect("Provider did not initialize"),
        )
        .await?;

        let addr = self.listen_address.clone();

        let data = Arc::new(self);
        HttpServer::new(move || {
            App::new()
                .wrap(Logger::default())
                .app_data(Data::new(data.clone()))
                .service(post_validate)
                .service(post_mutate)
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

#[post("/validate", guard = "json_guard")]
async fn post_validate(admission_review: Json<Value>) -> Json<AdmissionReview<DynamicObject>> {
    let json = admission_review.into_inner();
    let ret = match serde_json::from_value::<AdmissionReview<DynamicObject>>(json) {
        Ok(ar) => {
            // One may use `ar.request` according to doc. But that is wrong. `try_into` is the proper way.
            // `request` returns a broken `AdmissionRequest`, such as no api version and kind data.
            match ar.try_into() {
                Err(_) => AdmissionResponse::invalid("No request got"),
                Ok(req) => {
                    let ret = AdmissionResponse::from(&req);
                    if let Some(obj) = req.object {
                        tracing::debug!("Processing {:?}", req.kind);
                        if req.kind == *INGRESS_KIND.get().expect("INGRESS_KIND not initialized")
                            && let Ok(ingress) = dynamic_object2ingress(obj.clone())
                        {
                            validate_ingress(ret, ingress)
                        } else if GATEWAY_KINDS
                            .get()
                            .expect("GATEWAY_KINDs not initialized")
                            .contains(&req.kind)
                            && let Ok(gateway) = dynamic_object2gateway(obj.clone())
                        {
                            validate_gateway(ret, gateway).await
                        } else if HTTPROUTE_KINDS
                            .get()
                            .expect("HTTPROUTE_KINDs not initialized")
                            .contains(&req.kind)
                            && let Ok(httproute) = dynamic_object2httproute(obj)
                        {
                            validate_httproute(ret, httproute).await
                        } else {
                            ret.deny("")
                        }
                    } else {
                        ret.deny("")
                    }
                }
            }
        }
        Err(e) => AdmissionResponse::invalid(format!("{e:?}")),
    };
    Json(ret.into_review())
}

#[post("/mutate", guard = "json_guard")]
async fn post_mutate(
    admission_review: Json<Value>,
    conf: Data<Arc<Cli>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let json = admission_review.into_inner();
    let ret = match serde_json::from_value::<AdmissionReview<DynamicObject>>(json) {
        Ok(ar) => ar.try_into().map_or_else(
            |e| {
                tracing::error!("{e:?}");
                AdmissionResponse::invalid("No request got")
            },
            |req| {
                //mutate_ingress(&req, conf.get_ref()),
                let mut ret = AdmissionResponse::from(&req);
                if let Some(obj) = req.object {
                    if req.kind == *INGRESS_KIND.get().expect("INGRESS_KIND not initialized")
                        && let Ok(ingress) = dynamic_object2ingress(obj.clone())
                    {
                        mutate_ingress(ret, ingress, conf.get_ref())
                    } else if GATEWAY_KINDS
                        .get()
                        .expect("GATEWAY_KINDs not initialized")
                        .contains(&req.kind)
                        && let Ok(gateway) = dynamic_object2gateway(obj)
                    {
                        mutate_gateway(ret, gateway, conf.get_ref())
                    } else {
                        ret = ret.deny("");
                        ret
                    }
                } else {
                    ret = ret.deny("");
                    ret
                }
            },
        ),
        Err(e) => AdmissionResponse::invalid(format!("{e:?}")),
    };
    Json(ret.into_review())
}
