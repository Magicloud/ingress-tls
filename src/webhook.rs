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
    core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview},
};
use rustls::ServerConfig;
use serde_json::Value;

#[allow(clippy::wildcard_imports)]
use crate::{cli::Cli, helpers::*, ingress::*, tls_cert_resolver::TLSCertResolver};
use crate::{
    gateway::{mutate_gateway, validate_gateway},
    httproute::{mutate_httproute, validate_httproute},
};

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
    match post_validate_(admission_review).await {
        Ok(ret) => Json(ret.into_review()),
        Err(e) => Json(AdmissionResponse::invalid(format!("{e:?}")).into_review()),
    }
}

async fn post_validate_(admission_review: Json<Value>) -> Result<AdmissionResponse> {
    let json = admission_review.into_inner();
    let ar = serde_json::from_value::<AdmissionReview<DynamicObject>>(json)?;
    // One may use `ar.request` according to doc. But that is wrong. `try_into` is the proper way.
    // `request` returns a broken `AdmissionRequest`, such as no api version and kind data.
    let req =
        <AdmissionReview<DynamicObject> as TryInto<AdmissionRequest<DynamicObject>>>::try_into(ar)?;
    let mut ret = AdmissionResponse::from(&req);
    let final_result = if let Some(obj) = req.object {
        tracing::debug!("Processing {:?}", req.kind);
        if req.kind == *INGRESS_KIND.get().expect("INGRESS_KIND not initialized")
            && let Ok(ingress) = dynamic_object2ingress(obj.clone())
        {
            validate_ingress(&ingress)?
        } else if GATEWAY_KINDS
            .get()
            .expect("GATEWAY_KINDs not initialized")
            .contains(&req.kind)
            && let Ok(gateway) = dynamic_object2gateway(obj.clone())
        {
            // validate_gateway(Arc::new(gateway)).await
            todo!()
        } else if HTTPROUTE_KINDS
            .get()
            .expect("HTTPROUTE_KINDs not initialized")
            .contains(&req.kind)
            && let Ok(httproute) = dynamic_object2httproute(obj)
        {
            // validate_httproute(Arc::new(httproute)).await
            todo!()
        } else {
            unimplemented!()
        }
    } else {
        Status::Invalid("No object passed".to_string())
    };
    let ret = match final_result {
        Status::Allowed | Status::MoveOn => {
            ret.allowed = true;
            ret
        }
        Status::Denied(msg) => {
            if let DenyReason::InternalError(ref report) = msg {
                tracing::warn!("{:?}", report);
            }
            ret.deny(msg.to_string())
        }
        Status::Invalid(msg) => AdmissionResponse::invalid(msg),
        Status::Patch(_) => unimplemented!(),
    };
    Ok(ret)
}

#[post("/mutate", guard = "json_guard")]
async fn post_mutate(
    admission_review: Json<Value>,
    conf: Data<Arc<Cli>>,
) -> Json<AdmissionReview<DynamicObject>> {
    match post_mutate_(admission_review, conf).await {
        Ok(ret) => Json(ret.into_review()),
        Err(e) => Json(AdmissionResponse::invalid(format!("{e:?}")).into_review()),
    }
}

async fn post_mutate_(
    admission_review: Json<Value>,
    conf: Data<Arc<Cli>>,
) -> Result<AdmissionResponse> {
    let json = admission_review.into_inner();
    let ar = serde_json::from_value::<AdmissionReview<DynamicObject>>(json)?;
    let req = ar.try_into()?;
    let mut ret = AdmissionResponse::from(&req);
    let final_result = if let Some(obj) = req.object {
        if req.kind == *INGRESS_KIND.get().expect("INGRESS_KIND not initialized")
            && let Ok(ingress) = dynamic_object2ingress(obj.clone())
        {
            mutate_ingress(&ingress, &conf)?
        } else if GATEWAY_KINDS
            .get()
            .expect("GATEWAY_KINDs not initialized")
            .contains(&req.kind)
            && let Ok(gateway) = dynamic_object2gateway(obj.clone())
        {
            // mutate_gateway(Arc::new(gateway), &conf).await
            todo!()
        } else if HTTPROUTE_KINDS
            .get()
            .expect("HTTPROUTE_KINDs not initialized")
            .contains(&req.kind)
            && let Ok(httproute) = dynamic_object2httproute(obj)
        {
            // mutate_httproute(Arc::new(httproute)).await
            todo!()
        } else {
            unimplemented!()
        }
    } else {
        Status::Invalid("No object passed".to_string())
    };
    let ret = match final_result {
        Status::Allowed | Status::MoveOn => {
            ret.allowed = true;
            ret
        }
        Status::Denied(msg) => {
            if let DenyReason::InternalError(ref report) = msg {
                tracing::warn!("{:?}", report);
            }
            ret.deny(msg.to_string())
        }
        Status::Invalid(msg) => AdmissionResponse::invalid(msg),
        Status::Patch(p) => match ret.clone().with_patch(p) {
            Ok(ret) => ret,
            Err(e) => ret.deny(format!("{e:?}")),
        },
    };
    Ok(ret)
}
