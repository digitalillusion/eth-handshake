mod networkservice;
mod peer;
mod types;

use std::time::Duration;

use networkservice::NetworkService;
use secp256k1::SecretKey;
use types::*;

use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    tracing_subscriber::fmt::init();

    let service = NetworkService::new(
        vec![CapabilityId {
            name: "eth".to_string(),
            version: 68,
        }],
        SecretKey::new(&mut secp256k1::rand::thread_rng()),
    );

    let node : Enode = "enode://cc18ebf1077535196433f07bf6d5d6026a4d115b6b61ba7428ff46341cb3dd37275d15d26685aae2beb10b6e5b14e6d3d18d986baaba835145651f59efb6f9b9@127.0.0.1:30303".try_into()?;

    let _stream = service.connect(node).await?;

    sleep(Duration::from_secs(5)).await;
    Ok(())
}
