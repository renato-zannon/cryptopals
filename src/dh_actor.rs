// DH actors as used on challenges 34 & 35

use rand::prelude::*;

use std::sync::mpsc::{channel, Sender};
use std::thread::{self, JoinHandle};

use crate::{aes, dh};

#[derive(Debug)]
pub enum Protocol {
    Introduction(Sender<Protocol>),

    DHParameters {
        dh_params: dh::Parameters,
        public_key: dh::PublicKey,
    },

    PublicKey(dh::PublicKey),

    Encrypted {
        ciphertext: Vec<u8>,
        iv: [u8; 16],
    },
}

pub fn build_actor<F>(
    peer_tx: Option<Sender<Protocol>>,
    initial_message: Option<Vec<u8>>,
    f: F,
) -> DHActorHandle
where
    F: FnMut(Vec<u8>) -> DHAction + Send + 'static,
{
    let (tx, rx) = channel();

    let own_tx = tx.clone();
    let join_handle = thread::spawn(move || {
        let mut actor = DHActor::build(initial_message, f);

        if let Some(peer_tx) = peer_tx {
            actor.peer = Some(DHPeer {
                public_key: None,
                tx: peer_tx,
            });
            actor.send_introduction(own_tx);
        }

        for message in rx.iter() {
            if !actor.process(message) {
                return;
            }
        }
    });

    DHActorHandle { tx, join_handle }
}

pub struct DHActorHandle {
    pub tx: Sender<Protocol>,
    pub join_handle: JoinHandle<()>,
}

struct DHActor<F> {
    dh_params: Option<dh::Parameters>,
    public_key: Option<dh::PublicKey>,
    private_key: Option<dh::PrivateKey>,
    aes_key: Option<Vec<u8>>,
    peer: Option<DHPeer>,
    initial_message: Option<Vec<u8>>,
    process_encrypted: F,
}

struct DHPeer {
    public_key: Option<dh::PublicKey>,
    tx: Sender<Protocol>,
}

pub struct DHAction {
    pub reply_to_peer: Option<Vec<u8>>,
    pub keep_running: bool,
}

impl<F> DHActor<F>
where
    F: FnMut(Vec<u8>) -> DHAction,
{
    fn build(initial_message: Option<Vec<u8>>, process_encrypted: F) -> Self {
        Self {
            dh_params: None,
            public_key: None,
            private_key: None,
            aes_key: None,
            peer: None,
            process_encrypted,
            initial_message,
        }
    }

    fn process(&mut self, protocol_message: Protocol) -> bool {
        match protocol_message {
            Protocol::Introduction(tx) => {
                self.peer = Some(DHPeer {
                    public_key: None,
                    tx,
                });
                self.generate_and_send_dh_params();
                true
            }

            Protocol::DHParameters {
                dh_params,
                public_key,
            } => {
                self.dh_params = Some(dh_params);
                self.generate_keypair();
                self.set_peer_public_key(public_key);
                self.send_public_key();
                self.derive_session_key();
                self.send_initial_message();
                true
            }

            Protocol::PublicKey(public_key) => {
                self.set_peer_public_key(public_key);
                self.derive_session_key();
                self.send_initial_message();
                true
            }

            Protocol::Encrypted { ciphertext, iv } => {
                let decrypted = self.decrypt_message(&ciphertext, &iv);
                let action = (self.process_encrypted)(decrypted);

                if let Some(reply) = action.reply_to_peer {
                    self.send_to_peer(&reply);
                }

                action.keep_running
            }
        }
    }

    fn send_introduction(&self, own_tx: Sender<Protocol>) {
        self.peer().tx.send(Protocol::Introduction(own_tx)).unwrap();
    }

    fn generate_and_send_dh_params(&mut self) {
        let dh_params = dh::Parameters::default();
        self.dh_params = Some(dh_params.clone());
        self.generate_keypair();

        let public_key = self.public_key.clone().unwrap();

        let message = Protocol::DHParameters {
            dh_params,
            public_key,
        };

        self.peer().tx.send(message).unwrap();
    }

    fn send_public_key(&self) {
        let public_key = self
            .public_key
            .clone()
            .expect("Should have own public key by now");
        self.peer()
            .tx
            .send(Protocol::PublicKey(public_key))
            .unwrap();
    }

    fn generate_keypair(&mut self) {
        let params = self
            .dh_params
            .as_ref()
            .expect("Should have dh params already");
        let (public, private) = params.generate_keypair();

        self.public_key = Some(public);
        self.private_key = Some(private);
    }

    fn send_initial_message(&self) {
        if let Some(ref message) = self.initial_message {
            self.send_to_peer(message);
        }
    }

    fn send_to_peer(&self, message: &[u8]) {
        let iv: [u8; 16] = random();
        let aes_key = self
            .aes_key
            .as_ref()
            .expect("Should have derived AES key already");

        let ciphertext = aes::aes_128_cbc_encrypt(message, &aes_key, &iv);

        self.peer()
            .tx
            .send(Protocol::Encrypted { ciphertext, iv })
            .unwrap();
    }

    fn decrypt_message(&self, ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {
        let aes_key = self
            .aes_key
            .as_ref()
            .expect("Should have derived AES key already");

        aes::aes_128_cbc_decrypt(&ciphertext, &aes_key, &iv).unwrap()
    }

    fn derive_session_key(&mut self) {
        let params = self
            .dh_params
            .as_ref()
            .expect("Should have dh params already");
        let private_key = self
            .private_key
            .as_ref()
            .expect("Should have generated own keypair already");
        let peer_public_key = self
            .peer()
            .public_key
            .as_ref()
            .expect("Should have received peer public key by now");

        let session_key = params.derive_session_key(peer_public_key, private_key);
        self.aes_key = Some(session_key.to_aes_key());
    }

    fn set_peer_public_key(&mut self, public_key: dh::PublicKey) {
        let peer_mut = self.peer_mut();

        match &peer_mut.public_key {
            Some(old_key) => panic!(
                "Setting public key to peer that already had one: {:?}",
                old_key
            ),
            None => peer_mut.public_key = Some(public_key),
        }
    }

    fn peer(&self) -> &DHPeer {
        self.peer.as_ref().expect("Should have peer by now")
    }

    fn peer_mut(&mut self) -> &mut DHPeer {
        self.peer.as_mut().expect("Should have peer by now")
    }
}
