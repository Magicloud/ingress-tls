use std::{path::Path, sync::Arc};

use eyre::Result;
use inotify::{Inotify, WatchMask};
use rustls::{
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use smol::{Task, lock::RwLock, unblock};
use tracing::instrument;

// This is for Actix to hot-reload renewed TLS cert.
// In this application's certain case, there is only one cert.
// Hence no judgement from `client_hello.server_name()` or so.
#[derive(Debug)]
pub struct TLSCertResolver {
    inotify_thread: Option<Task<()>>,
    certified_key: Arc<RwLock<Arc<CertifiedKey>>>,
}
impl TLSCertResolver {
    #[instrument(skip_all)]
    pub async fn new(
        tls_folder: &Path,
        cert_file_name: &str,
        key_file_name: &str,
        provider: &CryptoProvider,
    ) -> Result<Self> {
        let cert_path = tls_folder.join(cert_file_name);
        let key_path = tls_folder.join(key_file_name);
        let mut self_ = Self {
            inotify_thread: None,
            certified_key: Arc::new(RwLock::new(Arc::new(CertifiedKey::from_der(
                CertificateDer::pem_file_iter(&cert_path)?
                    .flatten()
                    .collect(),
                PrivateKeyDer::from_pem_file(&key_path)?,
                provider,
            )?))),
        };
        let the_field = self_.certified_key.clone();
        let p = provider.clone();
        let t = tls_folder.to_path_buf();
        let inotify_thread = Some(unblock(move || {
            if let Err(e) = Self::watch(&the_field, &t, &cert_path, &key_path, &p) {
                tracing::error!("{e:?}");
            }
        }));
        self_.inotify_thread = inotify_thread;
        Ok(self_)
    }

    #[instrument(skip_all)]
    fn watch(
        the_field: &Arc<RwLock<Arc<CertifiedKey>>>,
        tls_folder: &Path,
        cert_file_path: &Path,
        key_file_path: &Path,
        provider: &CryptoProvider,
    ) -> Result<()> {
        let mut inotify = Inotify::init()?;
        inotify.watches().add(
            tls_folder,
            WatchMask::DELETE | WatchMask::CREATE | WatchMask::MOVED_TO,
        )?;

        let mut buffer = [0; 4096];
        loop {
            let events = inotify.read_events_blocking(&mut buffer)?;
            for event in events {
                if let Some(name) = event.name
                    && name == "..data"
                {
                    tracing::info!("TLS cert renewed");
                    *the_field.write_arc_blocking() = CertifiedKey::from_der(
                        CertificateDer::pem_file_iter(cert_file_path)?
                            .flatten()
                            .collect(),
                        PrivateKeyDer::from_pem_file(key_file_path)?,
                        provider,
                    )?
                    .into();
                    break;
                }
            }
        }
    }
}
impl ResolvesServerCert for TLSCertResolver {
    #[instrument(skip_all)]
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key.read_arc_blocking().clone())
    }
}
