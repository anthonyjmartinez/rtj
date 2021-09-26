use rtj::{Job, Message};

use crypto_box::SecretKey;
use rmp_serde as rmps;
use serde::{Serialize, Deserialize};

enum MsgType {
    Hello,
    Unknown
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
	let ack_string = format!("Hello from {}, aged {}", self.name, self.age);
	Vec::from(ack_string)
    }

    fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
	println!("{}", String::from_utf8(self.ack())?);
	Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    let hello = Hello {
	name,
	age,
    };

    // Build a message that can be encrypted for the recipient
    // The header contains the sender's public key and message
    // nonce. The recipient will use these values along with
    // their own private key to create the same crypto_box to
    // decrypt the payload.
    let msg = Message::new()
        .set_payload(&hello)
        .set_header(MsgType::Hello,
		    send_pub,
		    &mut rng)?;

    // Encrypt the message payload for the recipient.
    if let Ok(encrypted_to_recv) = msg.encrypt(recv_secret.public_key(), send_secret) {
	// Decrypt the message payload as the recipient
	if let Ok(hello_again) = encrypted_to_recv.decrypt(recv_secret) {
	    if let MsgType::Hello = hello_again.header.msgtype.into() {
		let hello = Hello::decode(&hello_again.payload);
		hello.run()?;
	    }
	}
    }

    Ok(())
}
