use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;

//128 byte secret containing forward/backward keys/digests
pub (crate) struct OnionSecret {
    secret: [u8; 128]
}

impl OnionSecret {
    pub (crate) fn new(dh_secret: &[u8; 32]) -> Self {
        let mut secret = [0; 128];

        //Take the dh_secret and stretch it into 128 bytes for the forward/backward key/digest
        pbkdf2::<Hmac<Sha256>>(dh_secret, &[0], 256, & mut secret);

        Self {
            secret,
        }
    }

    fn get_slice(&self, ind: usize) -> &[u8; 32] {
        (&self.secret[ind*32..ind*32+32]).try_into().unwrap()
    }

    pub (crate) fn forward_key(&self) -> &[u8; 32] {
        self.get_slice(0)
    }

    pub (crate) fn backward_key(&self) -> &[u8; 32] {
        self.get_slice(1)
    }

    pub (crate) fn forward_digest(&self) -> &[u8; 32] {
        self.get_slice(2)
    }

    pub (crate) fn backward_digest(&self) -> &[u8; 32] {
        self.get_slice(3)
    }
}
