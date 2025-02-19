use std::{collections::HashSet, str::FromStr, time::Instant};

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
    Litep2p, Litep2pEvent, PeerId,
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
    /// Prepopulate routing table with FIND_NODE queries before executing the main query.
    #[arg(long, value_name = "ITERATIONS", default_value_t = 0)]
    prepopulate: usize,
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

    let mut find_node_query = None;
    let mut get_providers_query = None;
    let mut iterations = args.prepopulate;

    if iterations > 0 {
        iterations -= 1;
        println!("Prepopulating Kademlia routing table...");
        find_node_query = Some(kademlia_handle.find_node(PeerId::random()).await);
    } else {
        println!("Running GET_PROVIDERS query...");
        get_providers_query = Some(
            kademlia_handle
                .get_providers(args.provider_key.clone())
                .await,
        );
    }

    let mut discovered_peers = HashSet::new();
    let mut contacted_peers = HashSet::new();
    let start = Instant::now();

    loop {
        tokio::select! {
            event = litep2p.next_event() => match event {
                Some(Litep2pEvent::ConnectionEstablished { peer, endpoint: _ }) => {
                    contacted_peers.insert(peer);
                },
                _ => {}
            },
            kademlia_event = kademlia_handle.next() => {
                let Some(kademlia_event) = kademlia_event else {
                    return Err(anyhow!("libp2p Kademlia terminated"))
                };

                match kademlia_event {
                    KademliaEvent::FindNodeSuccess { query_id, .. } if Some(query_id) == find_node_query => {
                        if iterations > 0 {
                            iterations -= 1;
                            find_node_query = Some(kademlia_handle.find_node(PeerId::random()).await);
                            println!("Prepopulating Kademlia routing table...");
                        } else {
                            println!("Running GET_PROVIDERS query...");
                            get_providers_query = Some(
                                kademlia_handle
                                    .get_providers(args.provider_key.clone())
                                    .await,
                            );
                        }
                    },
                    KademliaEvent::GetProvidersSuccess { query_id, provided_key, providers } => {
                        if Some(query_id) == get_providers_query && provided_key == args.provider_key {
                            print_statistics(&discovered_peers, &contacted_peers, &start);
                            print_providers(providers);
                            return Ok(())
                        }
                    },
                    KademliaEvent::QueryFailed { query_id } if Some(query_id) == find_node_query => {
                        print_statistics(&discovered_peers, &contacted_peers, &start);
                        return Err(anyhow!("FIND_NODE query failed"))
                    },
                    KademliaEvent::QueryFailed { query_id } if Some(query_id) == get_providers_query => {
                        print_statistics(&discovered_peers, &contacted_peers, &start);
                        return Err(anyhow!("Kademlia query failed"))
                    },
                    KademliaEvent::RoutingTableUpdate { peers } => {
                        for peer in peers {
                            discovered_peers.insert(peer);
                        }
                    },
                    event => {
                        println!("kademlia event: {event:?}");
                    }
                }
            }
        }
    }
}

fn print_statistics(discovered: &HashSet<PeerId>, contacted: &HashSet<PeerId>, start: &Instant) {
    println!("Discovered peers: {:?}", discovered.len());
    println!("Contacted peers: {:?}", contacted.len());
    println!("Time spent: {} s", start.elapsed().as_secs());
    println!("");
}

fn print_providers(providers: Vec<ContentProvider>) {
    for provider in providers {
        println!("{:?}", provider);
    }
}
