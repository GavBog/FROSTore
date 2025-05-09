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
    let mut swarm = Swarm::builder().build_and_exec()?;

    // Add the boot nodes to the client
    for boot_node in BOOT_NODES {
        let multiaddr: Multiaddr = boot_node.parse()?;
        eprintln!("Adding peer: {:?}", multiaddr);
        swarm.add_peer(multiaddr)?.await?;
    }
    eprintln!("Finished adding peers");

    // Generate a new keypair on the network
    let pubkey = swarm.generate(MIN_THRESHOLD, TOTAL_PEERS)?.1.await?;
    println!("Generated pubkey: {:?}", pubkey);

    // Sign some data
    let data = b"Hello, World!".to_vec();
    eprintln!("Signing data: {:?}", data);
    let signature = swarm.sign(pubkey, data.clone())?.1.await?;
    println!("Signature: {:?}", signature);

    // Verify the signature
    let valid = pubkey.verify(&data, &signature).is_ok();
    println!("Signature Valid: {}", valid);
    assert!(valid);
    Ok(())
}
