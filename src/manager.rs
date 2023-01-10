use std::collections::HashMap;
use sha2::{Sha256, Digest};
use x25519_dalek::{EphemeralSecret, PublicKey};
use crate::onion_secret::OnionSecret;
use crate::{Cell, CellType};

enum State {
    Ready,

    //State representing an End node
    End,

    //State representing a middle node
    Middle,
}

struct CircuitData {
    state: State,

    secret: Option<OnionSecret>,
}

impl CircuitData {

    fn new() -> Self {
        Self {
            state: State::Ready,
            secret: None,
        }
    }


}

pub struct Manager {
    map: HashMap<u32, CircuitData>,
}

unsafe impl Send for Manager {

}

impl Manager {


    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    //Used when a relay cell is received during an End or Middle state
    fn relay() {

    }

    //Any output that should be sent to the forward node
    fn output(&mut self, cell: &Cell) -> (Option<Cell>, Option<Cell>) {

        let data = self.map.get_mut(&cell.circuit_id).unwrap();

        match data.state {
            State::Ready => {

                if let CellType::Create { public_x } = cell.data {
                    //Setup the DH scheme
                    let server_secret = EphemeralSecret::new(rand::rngs::OsRng);
                    let server_public = PublicKey::from(&server_secret);

                    // Calculate the shared secret
                    let onion_secret = server_secret.diffie_hellman(&PublicKey::from(public_x)).to_bytes();

                    data.secret = Some(OnionSecret::new(&onion_secret));

                    //Calculate thee hash of the shared secret
                    let mut hasher = Sha256::new();

                    hasher.update(&onion_secret);

                    let ga = hasher.finalize();

                    let calculated_hash = ga.as_slice();

                    //Send the created ack
                    (Some(Cell { circuit_id: cell.circuit_id, data: CellType::Created {public_y: server_public.to_bytes(), hash: calculated_hash.try_into().unwrap()} }), None)

                } else {
                    (None, None)
                }

            }
            State::End => {(None, None)}
            State::Middle => {(None, None)}
        }
    }

    fn transition(&mut self, cell: &Cell) -> Option<State> {

        let data = self.map.get_mut(&cell.circuit_id).unwrap();

        match data.state {
            State::Ready => {

                if let CellType::Create { .. } = cell.data {
                    Some(State::End)
                } else {
                    None
                }

            }
            State::End => {None}
            State::Middle => {None}
        }
    }

    pub fn process(& mut self, cell: &Cell) -> (Option<Cell>, Option<Cell>) {
        //If the cell is a create, add it to the map
        if let CellType::Create { .. } = cell.data {

            if self.map.contains_key(&cell.circuit_id) {
                eprintln!("Circuit ID conflict")
            }

            self.map.insert(cell.circuit_id, CircuitData::new());
        }

        let output = self.output( cell);

        if let Some(new_state) = self.transition(cell) {
            self.map.get_mut(&cell.circuit_id).unwrap().state = new_state;
        }

        return output

    }

}
