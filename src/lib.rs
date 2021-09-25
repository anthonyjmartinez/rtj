// rtj provides a generic job execution framework in Rust
// Copyright 2021 Anthony Martinez
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use rand::{CryptoRng, RngCore};
use rmp_serde as rmps;
use serde::{Deserialize, Serialize};

/// [`Header`] contains identifying information about the [`Message`]
/// that follows. Specifically this contains the fields:
/// - msgtype, the [`Message`] type: `u8`
/// - psize, the following payload size in bytes as: `u32`
/// - pubkey, the crypto-box pubkey of the sender as: `[u8; 32]`
/// - nonce, the message nonce as: `[u8; 24]`
#[derive(Default, Debug, Copy, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Header {
    msgtype: u8,
    psize: u32,
    pubkey: [u8; 32],
    nonce: [u8; 24],
}

impl Header {
    /// Creates a new [`Header`] with default values 
    pub fn new() -> Header {
	Header::default()
    }

    /// Sets the value of [`Header.msgtype`] from any `T` implementing `Into<u8>`.
    pub fn set_msgtype<T: Into<u8>>(mut self, msgtype: T) -> Header {
	self.msgtype = msgtype.into();
	self
    }

    /// Sets the value of [`Header.psize`] from any `T` implementing `Into<u32>`.
    pub fn set_psize<T: Into<u32>>(mut self, psize: T) -> Header {
	self.psize = psize.into();
	self
    }

    /// Sets the value of [`Header.pubkey`] from any `T` implementing `Into<[u8; 32]>`.
    pub fn set_pubkey<T: Into<[u8; 32]>>(mut self, pubkey: T) -> Header {
	self.pubkey = pubkey.into();
	self
    }

    /// Sets the value of [`Header.nonce`] by generating one using the specified csprng.
    pub fn set_nonce<T: RngCore + CryptoRng>(mut self, csprng: &mut T) -> Result<Header, Box<dyn std::error::Error>> {
	let mut nonce: [u8; 24] = [0u8; 24];
	csprng.try_fill_bytes(&mut nonce)?;
	self.nonce = nonce;
	Ok(self)
    }

    /// Returns [`Header`] as a byte array `[u8; 64]`.
    pub fn to_bytes(self) -> [u8; 64] {
	let mut header_bytes = [0u8; 64];
	let reserved = [0u8; 3];
	[self.msgtype].iter()
	    .chain(self.psize.to_be_bytes().iter())
	    .chain(self.pubkey.iter())
	    .chain(self.nonce.iter())
	    .chain(reserved.iter())
	    .enumerate()
	    .for_each(|(i, x)| header_bytes[i] = *x);

	header_bytes
    }
}

pub trait Job {
    fn encode(&self) -> Vec<u8>;
    fn decode(input: &[u8]) -> Self;
    fn ack(&self) -> Vec<u8>;
    fn run(&self) -> Vec<u8>;
}

/*

TODO: Complete Message implementation considering security and a clear process
for getting private keys loaded to memory from a TPM or HSM.

Need to also provide a simple store for target pubkeys - though it's possible
this should be a generic interface for flexibility. Provide another trait
and use this to define methods used to get keys from wherever it is you choose
to get them.

#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Message<T: Job> {
    header: Header,
    payload: T 
}

impl<T: Job> Message<T> {
    pub fn new(msgtype: u8, payload: T) -> Message<T> {
    }
    
    pub fn encrypt(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {

    }

    pub fn decrypt(&self) -> Result<T, Box<dyn std::error::Error>> {

    }
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    enum MsgType {
	Basic,
    }

    #[derive(Default, Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
    pub struct Hello {
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

    #[test]
    fn test_header_new() {
	let header = Header::new();

	assert_eq!(header.msgtype, 0u8);
	assert_eq!(header.psize, 0u32);
	assert_eq!(header.pubkey, [0u8; 32]);
	assert_eq!(header.nonce, [0u8; 24]);
    }

    #[test]
    fn test_header_msgtype() {
	let header = Header::new()
	    .set_msgtype(MsgType::Basic as u8);

	assert_eq!(header.msgtype, 0u8)
    }

    #[test]
    fn test_header_psize() {
	let header = Header::new()
	    .set_psize(10u32);

	assert_eq!(header.psize, 10);
    }

    #[test]
    fn test_header_pubkey() {
	let mut rng = rand::thread_rng();
	let secret_key = crypto_box::SecretKey::generate(&mut rng);
	let pubkey = secret_key.public_key().as_bytes().to_owned();
	let header = Header::new()
	    .set_pubkey(pubkey);

	assert_eq!(header.pubkey, pubkey);
    }

    #[test]
    fn test_header_nonce() {
	let mut rng = rand::thread_rng();
	let header = Header::new()
	    .set_nonce(&mut rng).unwrap();

	assert_ne!(header.nonce, [0u8; 24]);
    }

    #[test]
    fn test_header_bytes() {
	let mut rng = rand::thread_rng();
	let secret_key = crypto_box::SecretKey::generate(&mut rng);
	let pubkey = secret_key.public_key().as_bytes().to_owned();
	let header = Header::new()
	    .set_msgtype(MsgType::Basic as u8)
	    .set_psize(10u32)
	    .set_pubkey(pubkey)
	    .set_nonce(&mut rng).unwrap();

	let header_bytes = header.to_bytes();
	assert_eq!(header_bytes[..5], [0, 0, 0, 0, 10]);
	assert_eq!(header_bytes[5..37], pubkey);
	assert_ne!(header_bytes[37..61], [0u8; 24]);
	assert_eq!(header_bytes[61..], [0u8; 3]);
    }

    #[test]
    fn test_job_encode_decode() {
	let hello = Hello {
	    name: "Anthony J. Martinez".to_owned(),
	    age: 38,
	};

	let encoded = hello.encode();
	let decoded: Hello = Hello::decode(&encoded);

	assert_eq!(hello, decoded)
    }

    #[test]
    fn test_job_ack_run() {
	let hello = Hello {
	    name: "Anthony J. Martinez".to_owned(),
	    age: 38,
	};

	let hello_vec = hello.run();

	assert_eq!(hello_vec, Vec::from("Hello from Anthony J. Martinez, aged 38"))
    }

    #[test]
    fn test_message_new() {
	unreachable!()
    }

    #[test]
    fn test_message_encrypt() {
	unreachable!()
    }

    #[test]
    fn test_message_decrypt() {
	unreachable!()
    }
}
