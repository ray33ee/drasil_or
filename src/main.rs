mod onion_secret;

use std::net::SocketAddr;
use serde::{Serialize, Deserialize};

use futures::prelude::*;
use sha2::{Sha256, Digest};
use tokio::net::TcpListener;
use tokio_serde::formats::*;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use x25519_dalek::{EphemeralSecret, PublicKey};

#[derive(Serialize, Deserialize, Debug)]
enum RelayType {
    Extend{public_x: [u8; 32], ip: SocketAddr},
    Extended{public_y: [u8; 32], hash: [u8; 32]},
    Begin{ addr: String },
    Connected,
    Data,
}

#[derive(Serialize, Deserialize, Debug)]
enum CellType {
    Create{public_x: [u8; 32]},
    Created{public_y: [u8; 32], hash: [u8; 32]},
    Relay{recognised: u32, stream_id: u32, digest: u32, data: RelayType, padding: Vec<u8>},
}

#[derive(Serialize, Deserialize, Debug)]
struct Cell {
    hop_id: u32,
    data: CellType,
}


#[tokio::main]
pub async fn main() {
    // Bind a server socket
    let listener = TcpListener::bind("127.0.0.1:65432").await.unwrap();

    println!("listening on {:?}", listener.local_addr());

    loop {
        let (socket, _) = listener.accept().await.unwrap();

        // Delimit frames using a length header
        let length_delimited = Framed::new(socket, LengthDelimitedCodec::new());

        let mut framed_socket = tokio_serde::SymmetricallyFramed::new(
            length_delimited,
            SymmetricalBincode::<Cell>::default(),
        );

        // Spawn a task that prints all received messages to STDOUT
        tokio::spawn(async move {
            //Wait for the first cell
            while let Some(msg) = framed_socket.try_next().await.unwrap() {

                if let CellType::Create {public_x} = msg.data {

                    //Setup the DH scheme
                    let server_secret = EphemeralSecret::new(rand::rngs::OsRng);
                    let server_public = PublicKey::from(&server_secret);

                    // Calculate the shared secret
                    let onion_secret = server_secret.diffie_hellman(&PublicKey::from(public_x)).to_bytes();

                    //Calculate thee hash of the shared secret
                    let mut hasher = Sha256::new();

                    hasher.update(&onion_secret);

                    let ga = hasher.finalize();

                    let calculated_hash = ga.as_slice();

                    //Send the created ack
                    framed_socket
                        .send(Cell { hop_id: 0, data: CellType::Created {public_y: server_public.to_bytes(), hash: calculated_hash.try_into().unwrap()} })
                        .await
                        .unwrap();

                    println!("Shared: {:?}", onion_secret);

                } else {

                }


            }
        });
    }
}
