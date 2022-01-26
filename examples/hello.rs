// rtj provides a generic job execution framework in Rust
// Copyright 2021-2022 Anthony Martinez
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.use rtj::{Job, Message};

use rtj::{Job, Message};

use crypto_box::SecretKey;
use rmp_serde as rmps;
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

enum MsgType {
    Hello,
    Unknown,
}

impl From<u8> for MsgType {
    fn from(t: u8) -> MsgType {
        match t {
            0 => MsgType::Hello,
            _ => MsgType::Unknown,
        }
    }
}

impl From<MsgType> for u8 {
    fn from(t: MsgType) -> u8 {
        match t {
            MsgType::Hello => 0,
            MsgType::Unknown => 255,
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Hello {
    name: String,
    age: u8,
}

impl Job for Hello {
    fn encode(&self) -> Vec<u8> {
        rmps::to_vec(&self).unwrap()
    }

    fn decode(input: &[u8]) -> Hello {
        let hello: Hello = rmps::from_read(input).unwrap();
        hello
    }

    fn ack(&self) -> Vec<u8> {
        let ack_string = format!("Hello from {}, age {}", self.name, self.age);
        Vec::from(ack_string)
    }

    fn run(&self) -> Result<()> {
	let ack_string = String::from_utf8(self.ack())?;
	println!("{ack_string}");
        Ok(())
    }
}

fn main() -> Result<()> {
    let mut rng = rand::thread_rng();

    // Create the sender's keys
    // This would normally be loaded from a secure location
    let send_secret = SecretKey::generate(&mut rng);
    let send_pub = send_secret.public_key().as_bytes().to_owned();

    // Create the recipient's keys
    // This would normally exist on a remote node, and be loaded
    // from a secure location. The sender should have a copy of
    // the remote node's public key to encrypt towards.
    let recv_secret = SecretKey::generate(&mut rng);

    let name = "Anthony J. Martinez".to_owned();
    let age = 38;
    let hello = Hello { name, age };

    // Build a message that can be encrypted for the recipient
    // The header contains the sender's public key and message
    // nonce. The recipient will use these values along with
    // their own private key to create the same crypto_box to
    // decrypt the payload.
    let msg = Message::new()
        .set_payload(&hello)
        .set_header(MsgType::Hello, send_pub, &mut rng)?;

    // Encrypt the message payload for the recipient.
    let encrypted_to_recv = msg.encrypt(recv_secret.public_key(), send_secret)?;

    // Decrypt the message payload as the recipient.
    let hello_again = encrypted_to_recv.decrypt(recv_secret)?;

    // Verify the message type.
    if let MsgType::Hello = hello_again.header.msgtype.into() {
        // Deserialize the message payload as the correct type
        let hello = Hello::decode(&hello_again.payload);

        // Execute the runner method on the deserialized type
        hello.run()?;
    }

    Ok(())
}
