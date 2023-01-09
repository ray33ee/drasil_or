use crate::fsm::State;
use crate::{Cell, CellType};
use sha2::{Sha256, Digest};
use x25519_dalek::{EphemeralSecret, PublicKey};


pub (crate) struct Start;

impl State for Start {



    fn transition(&self, input: &Cell) -> Option<Box<dyn State>> {
        if let CellType::Create { .. } = input.data {
            Some(Box::new(Ready))
        } else {
            None
        }
    }

    fn output(&self, input: &Cell) -> Option<Cell> {
        if let CellType::Create { public_x } = input.data {
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
            Some(Cell { hop_id: 0, data: CellType::Created {public_y: server_public.to_bytes(), hash: calculated_hash.try_into().unwrap()} })

        } else {
            None
        }
    }
}

struct Ready;

impl State for Ready {
    fn transition(&self, input: &Cell) -> Option<Box<dyn State>> {
        None
    }

    fn output(&self, input: &Cell) -> Option<Cell> {
        None
    }
}

