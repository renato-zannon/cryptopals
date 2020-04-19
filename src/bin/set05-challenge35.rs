use rug::Integer;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cryptopals::{
    aes, dh,
    dh_actor::{self, Protocol},
    quote,
};

// a = rand()
// A = (g^a) % p
//
// b = rand()
// B = (g^b) % p
//
// s = (A^b) % p = (B^a) % p = (g^(ab)) % p

fn main() {
    run_mitm1();
    run_mitm2();
    run_mitm3();
}

fn run_mitm1() {
    println!("Running MITM 1: g = 1");

    // g_B = 1
    //
    // B = (g ^ b) % p = (1 ^ b) % p = 1
    // s_A = (B ^ a) % p = (1 ^ a) % p = 1

    run_mitm(
        |mut dh_params, public_key| {
            dh_params.base = Integer::from(1);
            (dh_params, public_key)
        },
        |_| vec![dh::SessionKey(Integer::from(1))],
    );
}

fn run_mitm2() {
    println!("\nRunning MITM 2: g = p");

    // g_B = p
    //
    // B = (g ^ b) % p = (p ^ b) % p = 0
    // s_A = (B ^ a) % p = (0 ^ a) % p = 0

    run_mitm(
        |mut dh_params, public_key| {
            dh_params.base = dh_params.modulus.clone();
            (dh_params, public_key)
        },
        |_| vec![dh::SessionKey(Integer::from(0))],
    );
}

fn run_mitm3() {
    println!("\nRunning MITM 3: g = p - 1");

    // g_B = p - 1
    //
    // B = (g ^ b) % p = ((p - 1) ^ b) % p
    // B is (p - 1) for odd b, or 1 for even b
    //
    // for odd b:
    //   B = p - 1
    //   s_A = (B ^ a) % p = ((p - 1) ^ a) % p
    //
    //   for odd a:
    //     s_A = p - 1
    //
    //   for even a:
    //     s_A = 1
    //
    // for even b:
    //   B = 1
    //   s_A = (B ^ a) % p = (1 ^ a) % p = 1
    //
    //  So, s_A is either 1 or (p - 1)

    let (p_tx, p_rx) = channel();

    run_mitm(
        move |mut dh_params, public_key| {
            dh_params.base = dh_params.modulus.clone();
            dh_params.base -= 1;
            p_tx.send(dh_params.base.clone()).unwrap();

            (dh_params, public_key)
        },
        move |_| {
            vec![
                dh::SessionKey(Integer::from(1)),
                dh::SessionKey(Integer::from(p_rx.recv().unwrap())),
            ]
        },
    );
}

fn run_mitm<F, G>(f: F, g: G)
where
    F: Fn(dh::Parameters, dh::PublicKey) -> (dh::Parameters, dh::PublicKey) + Send + 'static,
    G: Fn(&dh::Parameters) -> Vec<dh::SessionKey> + Send + 'static,
{
    let actor1 = dh_actor::build_actor(None, Some(quote::random().into_bytes()), actor_1_process);

    let (interceptor_handle, interceptor_tx) = Interceptor::start(actor1.tx.clone(), f, g);

    let _actor2 = dh_actor::build_actor(Some(interceptor_tx), None, actor_2_process);

    let intercepted_messages = interceptor_handle.join().unwrap();

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
        reply_to_peer: None,
        keep_running: false,
    }
}

struct Interceptor<F, G> {
    modify_parameters: F,
    session_keys: G,

    to_actor1: Sender<Protocol>,
    from_actor2: Receiver<Protocol>,
}

impl<F, G> Interceptor<F, G>
where
    F: Fn(dh::Parameters, dh::PublicKey) -> (dh::Parameters, dh::PublicKey) + Send + 'static,
    G: Fn(&dh::Parameters) -> Vec<dh::SessionKey> + Send + 'static,
{
    fn start(
        to_actor1: Sender<Protocol>,
        modify_parameters: F,
        session_keys: G,
    ) -> (JoinHandle<Vec<Vec<u8>>>, Sender<Protocol>) {
        let (from_actor2_tx, from_actor2) = channel::<Protocol>();

        let mut interceptor = Self {
            to_actor1,
            from_actor2,
            modify_parameters,
            session_keys,
        };

        let handle = thread::spawn(move || interceptor.intercept());

        (handle, from_actor2_tx)
    }

    fn intercept(&mut self) -> Vec<Vec<u8>> {
        let (from_actor1_tx, from_actor1) = channel();
        let mut messages = vec![];

        let intro_to_actor1 = Protocol::Introduction(from_actor1_tx);
        self.to_actor1.send(intro_to_actor1).unwrap();

        let to_actor2 = match self.from_actor2.recv() {
            Ok(Protocol::Introduction(to_actor2)) => to_actor2,
            _ => panic!("Didn't receive intro from Actor 2"),
        };

        let (dh_params, actor1_public_key) = match from_actor1.recv() {
            Ok(Protocol::DHParameters {
                dh_params,
                public_key,
            }) => (dh_params, public_key),
            _ => panic!("Didn't receive DH params from Actor 1"),
        };

        let (dh_params, actor1_public_key) = (self.modify_parameters)(dh_params, actor1_public_key);

        to_actor2
            .send(Protocol::DHParameters {
                public_key: actor1_public_key.clone(),
                dh_params: dh_params.clone(),
            })
            .unwrap();

        let actor2_public_key = match self.from_actor2.recv() {
            Ok(Protocol::PublicKey(public_key)) => public_key,
            _ => panic!("Didn't receive public key from Actor 2"),
        };

        self.to_actor1
            .send(Protocol::PublicKey(actor2_public_key))
            .unwrap();

        match from_actor1.recv_timeout(Duration::from_millis(100)) {
            Ok(Protocol::Encrypted { ciphertext, iv }) => {
                self.append_decrypted(&dh_params, &ciphertext, &iv, &mut messages);
            }

            Err(e) => panic!("{}", e),

            _ => panic!(),
        };

        messages
    }

    fn append_decrypted(
        &mut self,
        params: &dh::Parameters,
        ciphertext: &[u8],
        iv: &[u8],
        messages: &mut Vec<Vec<u8>>,
    ) {
        let possible_keys = (self.session_keys)(&params);

        let plaintext = possible_keys
            .into_iter()
            .find_map(|session_key| {
                let aes_key = session_key.to_aes_key();
                aes::aes_128_cbc_decrypt(ciphertext, &aes_key, iv).ok()
            })
            .unwrap();

        messages.push(plaintext);
    }
}
