use boring::{
    error::ErrorStack,
    x509::{
        store::{X509Store, X509StoreBuilder},
        X509,
    },
};
use rquest::{tls::Impersonate, Client};
use std::sync::LazyLock;

/// Loads statically the root certificates from the native certificate store.
fn load_static_root_certs() -> Option<&'static X509Store> {
    static CERT_STORE: LazyLock<Result<X509Store, ErrorStack>> = LazyLock::new(|| {
        let mut cert_store = X509StoreBuilder::new()?;
        for cert in rustls_native_certs::load_native_certs().certs {
            let cert = X509::from_der(&*cert)?;
            cert_store.add_cert(cert)?;
        }
        Ok(cert_store.build())
    });

    match CERT_STORE.as_ref() {
        Ok(cert_store) => {
            log::info!("Loaded root certs");
            Some(cert_store)
        }
        Err(err) => {
            log::error!("Failed to load root certs: {:?}", err);
            None
        }
    }
}

fn load_dynamic_root_certs() -> Result<X509Store, ErrorStack> {
    let mut cert_store = X509StoreBuilder::new()?;
    for cert in rustls_native_certs::load_native_certs().certs {
        let cert = X509::from_der(&*cert)?;
        cert_store.add_cert(cert)?;
    }
    log::info!("Loaded dynamic root certs");
    Ok(cert_store.build())
}

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    use_static_root_certs().await?;
    use_dynamic_root_certs().await?;
    Ok(())
}

async fn use_static_root_certs() -> Result<(), rquest::Error> {
    // Build a client to mimic Edge127
    let client = Client::builder()
        .impersonate(Impersonate::Edge127)
        .root_certs_store(load_static_root_certs)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}

async fn use_dynamic_root_certs() -> Result<(), rquest::Error> {
    let client = Client::builder()
        .impersonate(Impersonate::Edge127)
        .root_certs_store(load_dynamic_root_certs()?)
        .build()?;
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
