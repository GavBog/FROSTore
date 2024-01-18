use frostore::*;

static TOTAL_PEERS: u16 = 3;
static MIN_THRESHOLD: u16 = 2;
static BOOT_NODES: [&str; 1] =
    ["/ip4/127.0.0.1/tcp/63888/p2p/12D3KooWDThDUUhDC2bi26E8LhHKsvLZq4wi7dNN5zypNVucgbqx"];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the network client
    let mut swarm = Builder::default().build();
    swarm.exec();

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
        if let swarm::SwarmOutput::SwarmEvents(swarm::SwarmEvent::ConnectionEstablished {
            peer_id,
            ..
        }) = event
        {
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
