use std::time::Duration;

use futures::SinkExt;
use secp256k1::SecretKey;
use tokio_stream::StreamExt;
use tracing::{debug, error, info};

use crate::{peer::Peer, types::*};

use tokio::{
    net::TcpStream,
    sync::mpsc::UnboundedSender,
    sync::mpsc::{channel, unbounded_channel, Sender},
    time::sleep,
};

/// Duration under which to expect a Pong message
const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// Exposes the methods to interact with a remote peer
pub struct PeerControl {
    /// Signal channel that drives Ping messaging
    pings_tx: Sender<()>,
    /// Signal channel that drives disconnection messaging
    peer_disconnect_tx: UnboundedSender<DisconnectSignal>,
}

/// Implementation of the `PeerControl` struct
impl PeerControl {
    /// Sends a Ping signal and expects a Pong to be received under a given timeout
    pub fn ping(&self) {
        futures::executor::block_on(async {
            if self.pings_tx.send(()).await.is_ok() {
                sleep(PING_TIMEOUT).await;
            }
        });
    }
    /// Sends a disconnect signal
    pub fn disconnect(&self) {
        let _ = self.peer_disconnect_tx.send(DisconnectSignal {
            initiator: DisconnectInitiator::Local,
            reason: DisconnectReason::DisconnectRequested,
        });
    }
}

/// The structure responsible of dealing with the network layer
pub struct NetworkService {
    /// Capabilities available to this client
    capabilities: Vec<CapabilityInfo>,
    /// Secret key of this client
    secret_key: SecretKey,
}

/// Implementation of the `NetworkService` structure
impl NetworkService {
    /// Creates a new service
    ///
    /// ### Arguments
    ///  - capabilities: the provided [`CapabilityInfo`] list
    ///  - secret_key: a secret key
    ///
    /// ### Returns
    /// `NetworkService`
    pub fn new(capabilities: Vec<CapabilityInfo>, secret_key: SecretKey) -> Self {
        Self {
            capabilities,
            secret_key,
        }
    }

    /// Connects to another peer and then executes a closure to which the [`PeerControl`] is provided
    ///
    /// ### Arguments
    ///  - enode: The [`Enode`] to connect to
    ///  - then: The closure accepting [`PeerControl`] to allow interaction with the connected peer
    /// ### Returns
    /// Result of unit type or [`AnyError`]
    pub async fn connect_and_then(
        &self,
        enode: Enode,
        then: impl FnOnce(PeerControl),
    ) -> Result<(), AnyError> {
        let capabilities = self.capabilities.clone();
        let transport = TcpStream::connect(enode.addr).await?;
        let peer = Peer::handshake(transport, enode, capabilities, self.secret_key).await?;

        let control = self.spawn_control(peer).await;
        then(control);

        Ok(())
    }

    /// Wraps a [`Peer<T>`] with its [`PeerControl`]
    async fn spawn_control(&self, peer: Peer<TcpStream>) -> PeerControl {
        let (mut sink, mut stream) = futures::StreamExt::split(peer);
        let (peer_disconnect_tx, mut peer_disconnect_rx) = unbounded_channel::<DisconnectSignal>();

        let (pings_tx, mut pings_rx) = channel::<()>(1);
        let (pongs_tx, mut pongs_rx) = channel::<()>(1);

        tokio::spawn(async move {
            loop {
                let mut egress = None;
                tokio::select! {
                    // We ping the peer.
                    Some(_) = pings_rx.recv() => {
                        egress = Some(PeerMessage::Ping);
                    }
                    // Peer has pinged us.
                    Some(_) = pongs_rx.recv() => {
                        egress = Some(PeerMessage::Pong);
                    }
                    // Ping timeout or signal from ingress router.
                    Some(DisconnectSignal { initiator, reason }) = peer_disconnect_rx.recv() => {
                        if let DisconnectInitiator::Local = initiator {
                            egress = Some(PeerMessage::Disconnect(reason));
                        }
                    }
                    else => continue
                };

                if let Some(message) = egress {
                    debug!("Sending egress message: {:?}", message);
                    // Send egress message, force disconnect on error.
                    if let Err(e) = sink.send(message).await {
                        error!("Send message error {:?}", e);
                    }
                }
            }
        });

        let listen_peer_disconnect_tx = peer_disconnect_tx.clone();
        tokio::spawn(async move {
            while let Some(message) = stream.next().await {
                match message {
                    Err(e) => {
                        info!("Peer incoming error: {}", e);
                        break;
                    }
                    Ok(PeerMessage::Disconnect(reason)) => {
                        // Peer has requested disconnection.
                        let _ = listen_peer_disconnect_tx.send(DisconnectSignal {
                            initiator: DisconnectInitiator::Remote,
                            reason,
                        });
                    }
                    Ok(PeerMessage::Ping) => {
                        let _ = pongs_tx.send(()).await;
                    }
                    Ok(PeerMessage::Pong) => {}
                    Ok(PeerMessage::Subprotocol) => {}
                }
            }

            info!("Ingress stream is closed, disconnecting");
            // Ingress stream is closed, force disconnect the peer.
            let _ = listen_peer_disconnect_tx.clone().send(DisconnectSignal {
                initiator: DisconnectInitiator::Remote,
                reason: DisconnectReason::DisconnectRequested,
            });
        });

        PeerControl {
            pings_tx,
            peer_disconnect_tx,
        }
    }
}
