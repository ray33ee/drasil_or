mod onion_secret;
mod skin;
mod manager;

use std::net::SocketAddr;
use serde::{Serialize, Deserialize};

use futures::prelude::*;
use sha2::{Sha256, Digest};
use tokio::net::TcpListener;
use tokio_serde::formats::*;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use x25519_dalek::{EphemeralSecret, PublicKey};
use crate::manager::Manager;

#[derive(Serialize, Deserialize, Debug)]
pub enum RelayType {
    Extend{public_x: [u8; 32], ip: SocketAddr},
    Extended{public_y: [u8; 32   ], hash: [u8; 32]},
    Begin{ addr: String },
    Connected,
    Data,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum CellType {
    Create{public_x: [u8; 32]},
    Created{public_y: [u8; 32], hash: [u8; 32]},
    Relay{recognised: u64, digest: u64, stream_id: u32, data: RelayType, padding: Vec<u8>},
    Encrypted{ cipher_text: Vec<u8> },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Cell {
    circuit_id: u32,
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

            //let mut fsm = FSM::new();
            let mut m = Manager::new();

            //Wait for the first cell
            while let Some(msg) = framed_socket.try_next().await.unwrap() {

                let (output, _) = m.process(&msg);

                //First get the corresponding output
                //let out = fsm.output(&msg);

                //transition to next state
                //fsm.transition(&msg);

                //If there is one, send the output
                if let Some(out_cell) = output {
                    framed_socket
                        .send(out_cell)
                        .await
                        .unwrap();
                }

            }
        });
    }
}
