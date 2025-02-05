use std::str::FromStr;

use anyhow::{anyhow, Context};
use clap::Parser;
use futures::StreamExt;
use litep2p::{
    config::ConfigBuilder as Litep2pConfigBuilder,
    protocol::libp2p::kademlia::{
        ConfigBuilder as KademliaConfigBuilder, ContentProvider, KademliaEvent,
        RecordKey as KademliaKey,
    },
    transport::{tcp::config::Config as TcpConfig, websocket::config::Config as WsConfig},
    Litep2p, PeerId,
};
use multiaddr::{Multiaddr, Protocol};

const DEFAULT_BOOTNODE: &str =
    "/dns/polkadot-bootnode-0.polkadot.io/tcp/30333/p2p/12D3KooWSz8r2WyCdsfWHgPyvD8GKQdJ1UAiRmrcrs8sQB3fe2KU";
const DEFALT_PROTOCOL: &str =
    "/91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3/kad";

/// Parse a multiaddress into [`PeerId`] and [`Multiaddr`].
fn parse_multiaddress(addr: &str) -> Result<(PeerId, Multiaddr), anyhow::Error> {
    let addr = Multiaddr::from_str(addr).context("invalid multiaddress")?;
    let peer_id = match addr.iter().last() {
        Some(Protocol::P2p(multihash)) => PeerId::from_multihash(multihash)
            .map_err(|m| anyhow!("multihash is not a peer ID in a multiaddress: {m:?}"))?,
        _ => return Err(anyhow!("multiaddress doesn't contain peer ID")),
    };

    Ok((peer_id, addr))
}

/// Decode a Kademlia key from a hex string.
fn parse_key(hex: &str) -> Result<KademliaKey, hex::FromHexError> {
    hex::decode(hex).map(|bytes| KademliaKey::new(&bytes))
}

/// Query Kademlia DHT content provider records.
#[derive(Parser, Debug)]
struct Args {
    /// Key (hex) of the content provider record to query.
    #[arg(short, long, value_name = "KEY", value_parser = parse_key)]
    provider_key: KademliaKey,
    /// Bootnode multiaddress.
    #[arg(short, long, value_name = "MULTIADDR", value_parser = parse_multiaddress, default_value = DEFAULT_BOOTNODE)]
    bootnode: (PeerId, Multiaddr),
    /// Kademlia protocol name.
    #[arg(short, long, value_name = "PROTOCOL", default_value = DEFALT_PROTOCOL)]
    kad_proto: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let (kademlia_config, mut kademlia_handle) = KademliaConfigBuilder::new()
        .with_protocol_names(vec![args.kad_proto.into()])
        .with_known_peers(
            [(args.bootnode.0, vec![args.bootnode.1])]
                .into_iter()
                .collect(),
        )
        .build();

    let mut litep2p = Litep2p::new(
        Litep2pConfigBuilder::new()
            .with_tcp(TcpConfig {
                listen_addresses: Vec::new(),
                ..Default::default()
            })
            .with_websocket(WsConfig {
                listen_addresses: Vec::new(),
                ..Default::default()
            })
            .with_libp2p_kademlia(kademlia_config)
            .build(),
    )
    .context("litep2p initialization error")?;

    let query = kademlia_handle
        .get_providers(args.provider_key.clone())
        .await;

    let mut kademlia_handle = kademlia_handle.fuse();

    loop {
        tokio::select! {
            _event = litep2p.next_event() => {
                // if let Some(event) = event {
                //     println!("litep2p event: {event:?}");
                // } else {
                //     return Err(anyhow!("litep2p stream ended"))
                // }
            },
            kademlia_event = kademlia_handle.select_next_some() => {
                match kademlia_event {
                    KademliaEvent::GetProvidersSuccess { query_id, provided_key, providers } => {
                        if query_id == query && provided_key == args.provider_key {
                            print_providers(providers);
                            return Ok(())
                        }
                    },
                    KademliaEvent::QueryFailed { query_id } if query_id == query => {
                        return Err(anyhow!("Kademlia query failed"))
                    },
                    _event => {
                        // println!("kademlia event: {event:?}");
                    }
                }
            }
        }
    }
}

fn print_providers(providers: Vec<ContentProvider>) {
    for provider in providers {
        println!("{:?}", provider);
    }
}
