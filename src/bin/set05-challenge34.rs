use rug::Integer;
use std::sync::mpsc::{channel, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cryptopals::{
    aes, dh,
    dh_actor::{self, Protocol},
    quote,
};

fn main() {
    let actor1 = dh_actor::build_actor(None, Some(quote::random().into_bytes()), actor_1_process);

    let (monster_handle, monster_tx) = intercept(actor1.tx.clone());

    let _actor2 = dh_actor::build_actor(Some(monster_tx), None, actor_2_process);

    let intercepted_messages = monster_handle.join().unwrap();

    println!("Intercepted messages:");
    for message in intercepted_messages {
        println!("    - {}", String::from_utf8_lossy(&message));
    }
}

fn actor_1_process(_message: Vec<u8>) -> dh_actor::DHAction {
    dh_actor::DHAction {
        reply_to_peer: None,
        keep_running: false,
    }
}

fn actor_2_process(_message: Vec<u8>) -> dh_actor::DHAction {
    dh_actor::DHAction {
        reply_to_peer: Some(quote::random().into_bytes()),
        keep_running: false,
    }
}

fn intercept(to_actor1: Sender<Protocol>) -> (JoinHandle<Vec<Vec<u8>>>, Sender<Protocol>) {
    let (from_actor1_tx, from_actor1) = channel();
    let (from_actor2_tx, from_actor2) = channel();

    let handle = thread::spawn(move || {
        let mut messages = vec![];
        // let mut actor2 = None;

        let intro_to_actor1 = Protocol::Introduction(from_actor1_tx);
        to_actor1.send(intro_to_actor1).unwrap();

        let to_actor2 = match from_actor2.recv() {
            Ok(Protocol::Introduction(to_actor2)) => to_actor2,
            _ => panic!("Didn't receive intro from Actor 2"),
        };

        let dh_params = match from_actor1.recv() {
            Ok(Protocol::DHParameters { dh_params, .. }) => dh_params,
            _ => panic!("Didn't receive DH params from Actor 1"),
        };

        let modulus = dh_params.modulus.clone();

        to_actor2
            .send(Protocol::DHParameters {
                public_key: dh::PublicKey(modulus.clone()),
                dh_params,
            })
            .unwrap();

        match from_actor2.recv() {
            Ok(Protocol::PublicKey { .. }) => {}
            _ => panic!("Didn't receive public key from Actor 2"),
        };

        to_actor1
            .send(Protocol::PublicKey(dh::PublicKey(modulus.clone())))
            .unwrap();

        loop {
            match from_actor1.recv_timeout(Duration::from_millis(10)) {
                Ok(Protocol::Encrypted { ciphertext, iv }) => {
                    append_decrypted(&ciphertext, &iv, &mut messages);
                    to_actor2
                        .send(Protocol::Encrypted { ciphertext, iv })
                        .unwrap();
                }

                _ => break,
            };

            match from_actor2.recv_timeout(Duration::from_millis(10)) {
                Ok(Protocol::Encrypted { ciphertext, iv }) => {
                    append_decrypted(&ciphertext, &iv, &mut messages);
                    to_actor1
                        .send(Protocol::Encrypted { ciphertext, iv })
                        .unwrap();
                }

                _ => break,
            };
        }

        messages
    });

    (handle, from_actor2_tx)
}

fn append_decrypted(ciphertext: &[u8], iv: &[u8], messages: &mut Vec<Vec<u8>>) {
    let aes_key = dh::SessionKey(Integer::from(0)).to_aes_key();
    let plaintext = aes::aes_128_cbc_decrypt(ciphertext, &aes_key, iv).unwrap();

    messages.push(plaintext);
}
