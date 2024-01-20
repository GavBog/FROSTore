<div align="center">
<pre>
    __________  ____  ___________              
   / ____/ __ \/ __ \/ ___/_  __/___  ________ 
  / /_  / /_/ / / / /\__ \ / / / __ \/ ___/ _ \
 / __/ / _, _/ /_/ /___/ // / / /_/ / /  /  __/
/_/   /_/ |_|\____//____//_/  \____/_/   \___/
-------------------------------------------------
Ed25519 Threshold Signature Database
</pre>

[![Crates.io](https://img.shields.io/crates/v/frostore.svg)](https://crates.io/crates/frostore)
[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
</div>

## Introduction

**FROSTore is a tool to prevent your Private Key from being compromised and used to sign data without your permission.**

FROSTore allows you to use Ed25519 threshold signatures to bring distributed trust to your application. Keys generated
by FROSTore are never combined into a single key, and are never stored on any single device. This means that even if a
device is compromised, your private key is still safe.

## Features

- [x] Create, store, and manage threshold signatures
- [x] Sign data with threshold signatures
- [x] Distributed Key Generation (DKG)
- [x] Customizable Minimum and Maximum thresholds

## Example

A basic example of how to use FROSTore to generate a keypair (using DKG) and sign some data.

```rust
use frostore::*;

static TOTAL_PEERS: u16 = 3;
static MIN_THRESHOLD: u16 = 2;
static BOOT_NODES: [&str; 3] = [
    "/ip4/127.0.0.1/tcp/63888/p2p/12D3KooWDThDUUhDC2bi26E8LhHKsvLZq4wi7dNN5zypNVucgbqx",
    "/ip4/127.0.0.1/tcp/58521/p2p/12D3KooWEk8vk2vFp7qTbif7X5kjQGJorFThxu8LheTF22Ef2fRc",
    "/ip4/127.0.0.1/tcp/58560/p2p/12D3KooWDs3SvAP4pfQAdqse9AroqaAsxDuswV6iFkc6aAwJooVu",
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the network client
    let mut swarm = Builder::default().build();
    swarm.exec()?;

    // Add the boot nodes to the client
    for boot_node in BOOT_NODES.iter() {
        let multiaddr: Multiaddr = boot_node.parse()?;
        swarm.add_peer(multiaddr)?;
    }

    // Wait for the client to connect to enough peers
    let mut peer_count = 0;
    loop {
        // Wait for the next event
        let event = swarm.next().await.unwrap();
        // If the event is a connection established event, increment the peer count
        if let swarm::SwarmOutput::SwarmEvents(swarm::SwarmEvent::ConnectionEstablished { peer_id, .. }) = event {
            eprintln!("Connected to peer: {}", peer_id);
            peer_count += 1;
            eprintln!("Peer count: {}", peer_count);
        }
        if peer_count >= TOTAL_PEERS {
            break;
        }
    }
    eprintln!("Finished adding peers");

    // Generate a new keypair on the network
    let pubkey = swarm.generate(MIN_THRESHOLD, TOTAL_PEERS).1.await?;
    println!("Generated pubkey: {:?}", pubkey);

    // Sign some data
    let data = b"Hello, World!".to_vec();
    eprintln!("Signing data: {:?}", data);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let signature = swarm.sign(pubkey, data.clone()).1.await?;
    println!("Signature: {:?}", signature);

    // Verify the signature
    let valid = pubkey.verify(&data, &signature).is_ok();
    println!("Signature Valid: {}", valid);
    assert!(valid);
    Ok(())
}
```

We have provided a few more examples to help you get started. You can find them in the [`/examples/`](examples)
directory.

For more information on how to use FROSTore, please check our [docs](https://docs.rs/frostore).

## Research

FROSTore is primarily based on the following research papers:

- [Two-Round Threshold Schnorr Signatures with FROST](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/)
- [FROST: Flexible Round-Optimized Schnorr Threshold Signatures](https://eprint.iacr.org/2020/852.pdf)

## Disclaimers

This is a work in progress and is in **BETA**. It is not ready for production use.
