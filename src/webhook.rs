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
use tracing::instrument;
use tracing_actix_web::TracingLogger;

#[allow(clippy::wildcard_imports)]
use crate::{
    cli::Cli, gateway::*, helpers::*, httproute::*, ingress::*, tls_cert_resolver::TLSCertResolver,
};

impl Cli {
    pub async fn start(self) -> Result<()> {
        let cert_solver = TLSCertResolver::new(
            &self.tls_folder,
            &self.tls_certificate_file_name,
            &self.tls_private_key_file_name,
            rustls::crypto::CryptoProvider::get_default().expect("Provider did not initialize"),
        )
        .await?;

        let addr = self.listen_address.clone();

        let data = Arc::new(self);
        HttpServer::new(move || {
            App::new()
                .wrap(Logger::default())
                .wrap(TracingLogger::default())
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
    post_validate_(admission_review)
        .await
        .map_or_else(|_| todo!(), |ret| Json(ret.into_review()))
}

#[instrument(skip_all)]
async fn post_validate_(admission_review: Json<Value>) -> Result<AdmissionResponse> {
    let empty_string = String::new();
    let json = admission_review.into_inner();
    let ar = serde_json::from_value::<AdmissionReview<DynamicObject>>(json)?;
    // One may use `ar.request` according to doc. But that is wrong. `try_into` is the proper way.
    // `request` returns a broken `AdmissionRequest`, such as no api version and kind data.
    let req =
        <AdmissionReview<DynamicObject> as TryInto<AdmissionRequest<DynamicObject>>>::try_into(ar)?;
    let ret = AdmissionResponse::from(&req);
    let k = &req.kind.kind;
    let ns = req
        .object
        .as_ref()
        .and_then(|o| o.metadata.namespace.as_ref())
        .unwrap_or(&empty_string);
    let n = req
        .object
        .as_ref()
        .and_then(|o| o.metadata.name.as_ref())
        .unwrap_or(&empty_string);
    tracing::info!(target: "validate", message = format!("Processing {} {}/{}", k, ns, n));
    let final_result = if let Some(obj) = req.object.clone() {
        let dot = obj.types.as_ref().map(|t| &t.kind);
        let ret = if dot.is_some_and(|x| x == "Ingress") {
            let ingress = dynamic_object2ingress(obj)?;
            validate_ingress().run(Arc::new(ingress)).await
        } else if dot.is_some_and(|x| x == "Gateway") {
            let gateway = dynamic_object2gateway(obj)?;
            validate_gateway().run(Arc::new(gateway)).await
        } else if dot.is_some_and(|x| x == "HTTPRoute") {
            let httproute = dynamic_object2httproute(obj)?;
            validate_httproute().run(Arc::new(httproute)).await
        } else {
            unimplemented!()
        };
        ret.into()
    } else {
        Status::Invalid("No object passed".to_string())
    };
    tracing::info!(target: "validate", message = format!("Result of {} {}/{}: {:?}", k, ns, n, final_result));

    let x: StatusAdmissionResponse = (final_result, ret, (ns, n)).into();
    Ok(x.into())
}

#[post("/mutate", guard = "json_guard")]
async fn post_mutate(
    admission_review: Json<Value>,
    conf: Data<Arc<Cli>>,
) -> Json<AdmissionReview<DynamicObject>> {
    (post_mutate_(admission_review, conf).await)
        .map_or_else(|_| todo!(), |ret| Json(ret.into_review()))
}

async fn post_mutate_(
    admission_review: Json<Value>,
    conf: Data<Arc<Cli>>,
) -> Result<AdmissionResponse> {
    let empty_string = String::new();
    let json = admission_review.into_inner();
    let ar = serde_json::from_value::<AdmissionReview<DynamicObject>>(json)?;
    let req = ar.try_into()?;
    let ret = AdmissionResponse::from(&req);
    let k = &req.kind.kind;
    let ns = req
        .object
        .as_ref()
        .and_then(|o| o.metadata.namespace.as_ref())
        .unwrap_or(&empty_string);
    let n = req
        .object
        .as_ref()
        .and_then(|o| o.metadata.name.as_ref())
        .unwrap_or(&empty_string);
    tracing::info!(target: "mutate", message = format!("Processing {} {}/{}", k, ns, n));
    let final_result = if let Some(obj) = req.object.clone() {
        let dynamic_object_type = obj.types.as_ref().map(|t| &t.kind);
        let ret = if dynamic_object_type.is_some_and(|x| x == "Ingress") {
            let ingress = dynamic_object2ingress(obj)?;
            mutate_ingress(Arc::new(ingress), &conf).await
        } else if dynamic_object_type.is_some_and(|x| x == "Gateway") {
            let gateway = dynamic_object2gateway(obj)?;
            mutate_gateway(Arc::new(gateway), &conf).await
        } else if dynamic_object_type.is_some_and(|x| x == "HTTPRoute") {
            let httproute = dynamic_object2httproute(obj)?;
            mutate_httproute(Arc::new(httproute)).await
        } else {
            unimplemented!()
        };
        ret.into()
    } else {
        Status::Invalid("No object passed".to_string())
    };
    tracing::info!(target: "mutate", message = format!("Result of {} {}/{}: {:?}", k, ns, n, final_result));

    let x: StatusAdmissionResponse = (final_result, ret, (ns, n)).into();
    Ok(x.into())
}
