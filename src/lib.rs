// rtj provides a generic job execution framework in Rust
// Copyright 2021 Anthony Martinez
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crypto_box::{self, rand_core::{CryptoRng, RngCore}};

/// [`Header`] contains identifying information about the [`Message`]
/// that follows. Specifically this contains the fields:
/// - msgtype, the [`Message`] type: `u8`
/// - psize, the following payload size in bytes as: `u32`
/// - pubkey, the crypto-box pubkey of the sender as: `[u8; 32]`
/// - nonce, the message nonce as: `[u8; 24]`
#[derive(Default, Debug, Copy, Clone)]
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

    /// Sets the value of [`Header.nonce`] using the specified csprng.
    pub fn set_nonce<T: RngCore + CryptoRng>(mut self, csprng: &mut T) -> Result<Header, Box<dyn std::error::Error>> {
	let mut nonce: [u8; 24] = [0u8; 24];
	csprng.try_fill_bytes(&mut nonce)?;
	self.nonce = nonce;
	Ok(self)
    }

    /// Returns [`Header`] as a byte array `[u8; 64]`.
    pub fn to_bytes(self) -> [u8; 64] {
	let mut pos = 0;
	let mut header_bytes = [0u8; 64];
	header_bytes[pos] = self.msgtype;
	pos += 1;

	pos = copy_bytes_to_position(&self.psize.to_be_bytes(), &mut header_bytes, pos);
	pos = copy_bytes_to_position(&self.pubkey, &mut header_bytes, pos);
	let _pos = copy_bytes_to_position(&self.nonce, &mut header_bytes, pos);
	
	header_bytes
    }
}

fn copy_bytes_to_position(src: &[u8], dest: &mut [u8], position: usize) -> usize {
    let mut position = position;
    for b in src.iter() {
	dest[position] = *b;
	position += 1;
    }

    position
}

pub trait Message {
}

#[cfg(test)]
mod tests {
    use super::*;

    enum MsgType {
	Basic,
    }

    #[test]
    fn test_header() {
	let mut rng = rand::thread_rng();
	let secret_key = crypto_box::SecretKey::generate(&mut rng);
	let pubkey = secret_key.public_key().as_bytes().to_owned();
	let header = Header::new()
	    .set_msgtype(MsgType::Basic as u8)
	    .set_psize(10u32)
	    .set_pubkey(pubkey)
	    .set_nonce(&mut rng).unwrap();

	assert_eq!(header.msgtype, 0u8);
	assert_eq!(header.psize, 10);
	assert_eq!(header.pubkey, pubkey);
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
}
