use std::time::Duration;

use futures::SinkExt;
use secp256k1::SecretKey;
use tokio_stream::StreamExt;
use tracing::{debug, info};

use crate::{peer::Peer, types::*};

use tokio::{
    net::TcpStream,
    sync::mpsc::{channel, unbounded_channel, Sender},
    sync::{oneshot::Sender as OneShotSender, mpsc::UnboundedSender},
    time::sleep,
};

const GRACE_PERIOD_SECP256K1S: u64 = 2;
const PING_TIMEOUT: Duration = Duration::from_secs(5);

pub struct PeerControl {
    pings_tx: Sender<OneShotSender<()>>,
    peer_disconnect_tx: UnboundedSender<DisconnectSignal>,  
}

impl PeerControl {
    pub async fn ping(&self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.pings_tx.send(tx).await.is_ok() && rx.await.is_ok() {
            sleep(PING_TIMEOUT).await;
        }
    }
    pub fn disconnect(&self) {
        let _ = self.peer_disconnect_tx.send(DisconnectSignal {
            initiator: DisconnectInitiator::Local,
            reason: DisconnectReason::DisconnectRequested,
        });
    }
}

pub struct NetworkService {
    capabilities: Vec<CapabilityInfo>,
    secret_key: SecretKey,
}

impl NetworkService {
    pub fn new(capabilities: Vec<CapabilityInfo>, secret_key: SecretKey) -> Self {
        Self {
            capabilities,
            secret_key,
        }
    }

    pub async fn connect_and_then(
        &self,
        enode: Enode,
        then: impl FnOnce(PeerControl),
    ) -> Result<(), AnyError>
    {
        let capabilities = self.capabilities.clone();
        let transport = TcpStream::connect(enode.addr).await?;
        let peer = Peer::handshake(transport, enode, capabilities, self.secret_key).await?;

        let control = self.spawn_control(peer).await;
        then(control);

        Ok(())
    }

    pub async fn spawn_control(&self, peer: Peer<TcpStream>) -> PeerControl {
        let (mut sink, mut stream) = futures::StreamExt::split(peer);
        let (peer_disconnect_tx, mut peer_disconnect_rx) = unbounded_channel::<DisconnectSignal>();

        let (pings_tx, mut pings_rx) = channel::<OneShotSender<()>>(1);
        let (pongs_tx, mut pongs_rx) = channel::<()>(1);

        tokio::spawn(async move {
            loop {
                let mut disconnecting = None;
                let mut egress = None;
                let mut trigger: Option<OneShotSender<()>> = None;
                tokio::select! {
                    // We ping the peer.
                    Some(tx) = pings_rx.recv() => {
                        egress = Some(PeerMessage::Ping);
                        trigger = Some(tx);
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
                        disconnecting = Some(DisconnectSignal { initiator, reason })
                    }
                };

                if let Some(message) = egress {
                    debug!("Sending egress message: {:?}", message);

                    // Send egress message, force disconnect on error.
                    if let Err(e) = sink.send(message).await {
                        info!("peer disconnected with error {:?}", e);
                        disconnecting.get_or_insert(DisconnectSignal {
                            initiator: DisconnectInitiator::LocalForceful,
                            reason: DisconnectReason::TcpSubsystemError,
                        });
                    } else if let Some(trigger) = trigger {
                        let _ = trigger.send(());
                    }
                }

                if let Some(DisconnectSignal { initiator, reason }) = disconnecting {
                    if let DisconnectInitiator::Local = initiator {
                        // We have sent disconnect message, wait for grace period.
                        sleep(Duration::from_secs(GRACE_PERIOD_SECP256K1S)).await;
                    }
                    info!(
                        "Received Disconnect message from {:?}: {:?}",
                        initiator, reason
                    );
                    break;
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
            peer_disconnect_tx
        }
    }
}
