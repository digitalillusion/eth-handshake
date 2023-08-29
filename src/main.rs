mod networkservice;
mod peer;
mod types;

use clap::Parser;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use networkservice::NetworkService;
use secp256k1::SecretKey;
use types::*;

/// Clap representation of the main arguments
#[derive(Parser)]
struct Cli {
    #[arg(required = true)]
    /// The list of enodes to connect ("enode://...")
    enodes: Vec<String>,
}

/// ### eth-handshake
///
/// This program implements the handshake toward an ethereum node using RLPx protocol
/// and verifies that the it was successful by exchanging Ping-Pong messages
#[tokio::main]
async fn main() -> Result<(), AnyError> {
    // Parse the command line arguments
    let args = Cli::parse();
    // Initialize the logger
    tracing_subscriber::fmt::init();

    // Instance the client
    let service = NetworkService::new(
        vec![CapabilityInfo {
            name: "eth".to_string(),
            version: 68,
        }],
        SecretKey::new(&mut secp256k1::rand::thread_rng()),
    );

    // Collector of all spawned tasks
    let mut tasks = FuturesUnordered::new();

    // Spawn a connection and then ping toward all the enodes passed as argument
    for node in args.enodes {
        let node: Enode = node.try_into()?;
        tasks.push(service.connect_and_then(node, |peer| {
            peer.ping();
            peer.disconnect();
        }));
    }

    // Await termination of all spawned tasks
    while tasks.next().await.is_some() {}

    Ok(())
}
