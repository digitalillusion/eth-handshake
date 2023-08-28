mod networkservice;
mod peer;
mod types;

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use networkservice::NetworkService;
use secp256k1::SecretKey;
use types::*;
use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[arg(required=true)]
    /// The list of enodes to connect ("enode://...")
    enodes: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    let args = Cli::parse();
    tracing_subscriber::fmt::init();

    let service = NetworkService::new(
        vec![CapabilityInfo {
            name: "eth".to_string(),
            version: 68,
        }],
        SecretKey::new(&mut secp256k1::rand::thread_rng()),
    );

    let mut tasks = FuturesUnordered::new();

    for node in args.enodes {
        let node : Enode = node.try_into()?;
        tasks.push(service.connect_and_then(node, |peer| {
            futures::executor::block_on(peer.ping());
            peer.disconnect();
        }));
    }

    while tasks.next().await.is_some() {}

    Ok(())
}
