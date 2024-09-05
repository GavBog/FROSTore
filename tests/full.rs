use anyhow::{anyhow, Result};
use frostore::*;
use std::collections::HashMap;
use swarm::{SwarmEvent, SwarmOutput};

#[tokio::test]
async fn gen_and_sign() -> Result<()> {
    let mut swarm_list = [
        Swarm::builder().build_and_exec()?,
        Swarm::builder().build_and_exec()?,
        Swarm::builder().build_and_exec()?,
        Swarm::builder().build_and_exec()?,
    ];

    let mut addresses = HashMap::new();
    loop {
        for (i, swarm) in swarm_list.iter_mut().enumerate() {
            if addresses.contains_key(&i) {
                continue;
            }
            if let SwarmOutput::SwarmEvents(SwarmEvent::NewListenAddr { address, .. }) =
                swarm.next().await.ok_or(anyhow!("Swarm exited"))?
            {
                let address = address
                    .with_p2p(swarm.key.public().to_peer_id())
                    .map_err(|_| anyhow!("Failed to add pubkey to multiaddr"))?;
                println!("Swarm {} listening on: {}", i, address);
                addresses.insert(i, address);
            }
        }
        if addresses.len() == swarm_list.len() {
            break;
        }
    }
    println!("Addresses: {:?}", addresses);

    for (i, swarm) in swarm_list.iter_mut().enumerate() {
        for (j, address) in addresses.iter() {
            if i == *j {
                continue;
            }
            println!("Adding peer {} to swarm {}", j, i);
            swarm.add_peer(address.clone())?.await?;
        }
    }
    println!("Added all peers");

    let pubkey = swarm_list[0].generate(2, 3)?.1.await?;
    println!("Generated pubkey: {:?}", pubkey);

    let message = b"hello".to_vec();
    println!("Signing message: {:?}", message);
    let signature = swarm_list[0].sign(pubkey, message)?.1.await?;
    println!("Signature: {:?}", signature);

    Ok(())
}
