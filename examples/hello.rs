use rtj::{Job, Message};

use crypto_box::SecretKey;
use rmp_serde as rmps;
use serde::{Serialize, Deserialize};

enum MsgType {
    Hello,
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

    fn run(&self) -> Vec<u8> {
	self.ack()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();

    // Create the sender's keys
    let send_secret = SecretKey::generate(&mut rng);
    let send_pub = send_secret.public_key().as_bytes().to_owned();

    // Create the recipient's keys
    let recv_secret = SecretKey::generate(&mut rng);

    let name = "Anthony J. Martinez".to_owned();
    let age = 38;
    let hello = Hello {
	name,
	age,
    };

    // Build a message that can be encrypted for the recipient
    let msg = Message::new()
        .set_payload(&hello)
        .set_header(MsgType::Hello as u8,
		    send_pub,
		    &mut rng)?;


    if let Ok(encrypted_to_recv) = msg.encrypt(recv_secret.public_key(), send_secret) {
	if let Ok(hello_again) = encrypted_to_recv.decrypt(recv_secret) {
	    println!("{:?}", hello_again)
	} else {
	    println!("oops - failed decrypt")
	}
    } else {
	println!("oops -failed encrypt")
    }

    
    Ok(())
}
