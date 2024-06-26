// rtj provides a generic job execution framework in Rust
// Copyright 2021-2024 Anthony Martinez
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::*;

/// [`Header`] contains identifying information about the [`Job`]
/// that follows.
///
/// Specifically this contains the fields:
/// - msgtype, the [`Job`] type: `u8`
/// - psize, the following payload size in bytes as: `u32`
/// - pubkey, the crypto-box pubkey of the sender as: `[u8; 32]`
/// - nonce, the message nonce as: `[u8; 24]`
/// - encrypted, `bool` indicating the encryption status of the following payload.
#[derive(Default, Debug, Copy, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Header {
    pub msgtype: u8,
    pub psize: u32,
    pub pubkey: [u8; 32],
    pub nonce: [u8; 24],
    pub encrypted: bool,
}

impl Header {
    /// Creates a new [`Header`] with default values
    pub fn new() -> Header {
        Header::default()
    }

    /// Sets the value of `msgtype`.
    pub fn set_msgtype<T: Into<u8>>(mut self, msgtype: T) -> Header {
        self.msgtype = msgtype.into();
        self
    }

    /// Sets the value of `psize`.
    pub fn set_psize<T: Into<u32>>(mut self, psize: T) -> Header {
        self.psize = psize.into();
        self
    }

    /// Sets the value of `pubkey`.
    pub fn set_pubkey<T: Into<[u8; 32]>>(mut self, pubkey: T) -> Header {
        self.pubkey = pubkey.into();
        self
    }

    /// Sets the value of `nonce` by generating one using the specified csprng.
    pub fn set_nonce<T: RngCore + CryptoRng>(mut self, csprng: &mut T) -> Result<Header> {
        let mut nonce: [u8; 24] = [0u8; 24];
        csprng.try_fill_bytes(&mut nonce)?;
        self.nonce = nonce;
        Ok(self)
    }

    /// Sets the value of `encrypted`.
    pub fn set_encrypted(mut self, encrypted: bool) -> Header {
        self.encrypted = encrypted;
        self
    }

    /// Returns [`Header`] as a byte array `[u8; 64]`.
    pub fn to_bytes(self) -> [u8; 64] {
        let mut header_bytes = [0u8; 64];
        let reserved = [0u8; 2];
        [self.msgtype]
            .iter()
            .chain(self.psize.to_be_bytes().iter())
            .chain(self.pubkey.iter())
            .chain(self.nonce.iter())
            .chain([self.encrypted as u8].iter())
            .chain(reserved.iter())
            .enumerate()
            .for_each(|(i, x)| header_bytes[i] = *x);

        header_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Testing with Rust MessagePack implementation for Serialization/Deserialization
    use rmp_serde as rmps;

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
	    let name = &self.name;
	    let age = &self.age;
            let ack_string = format!("Hello from {name}, aged {age}");
            Vec::from(ack_string)
        }

        fn run(&self) -> std::result::Result<(), Box<dyn std::error::Error>> {
            self.ack();
            Ok(())
        }
    }

    #[test]
    fn test_header_new() {
        let header = Header::new();

        assert_eq!(header.msgtype, 0u8);
        assert_eq!(header.psize, 0u32);
        assert_eq!(header.pubkey, [0u8; 32]);
        assert_eq!(header.nonce, [0u8; 24]);
        assert!(!header.encrypted);
    }

    #[test]
    fn test_header_msgtype() {
        let header = Header::new().set_msgtype(MsgType::Hello);

        assert_eq!(header.msgtype, 0u8)
    }

    #[test]
    fn test_header_psize() {
        let header = Header::new().set_psize(10u32);

        assert_eq!(header.psize, 10);
    }

    #[test]
    fn test_header_pubkey() {
        let mut rng = rand::thread_rng();
        let secret_key = crypto_box::SecretKey::generate(&mut rng);
        let pubkey = secret_key.public_key().as_bytes().to_owned();
        let header = Header::new().set_pubkey(pubkey);

        assert_eq!(header.pubkey, pubkey);
    }

    #[test]
    fn test_header_nonce() {
        let mut rng = rand::thread_rng();
        let header = Header::new().set_nonce(&mut rng).unwrap();

        assert_ne!(header.nonce, [0u8; 24]);
    }

    #[test]
    fn test_header_encrypted() {
        let header = Header::new().set_encrypted(true);

        assert!(header.encrypted)
    }
    #[test]
    fn test_header_bytes() {
        let mut rng = rand::thread_rng();
        let secret_key = crypto_box::SecretKey::generate(&mut rng);
        let pubkey = secret_key.public_key().as_bytes().to_owned();
        let header = Header::new()
            .set_msgtype(MsgType::Hello)
            .set_psize(10u32)
            .set_pubkey(pubkey)
            .set_nonce(&mut rng)
            .unwrap();

        let header_bytes = header.to_bytes();
        assert_eq!(header_bytes[..5], [0, 0, 0, 0, 10]);
        assert_eq!(header_bytes[5..37], pubkey);
        assert_ne!(header_bytes[37..61], [0u8; 24]);
        assert_eq!(header_bytes[61], 0u8);
        assert_eq!(header_bytes[62..], [0u8; 2]);
    }
}
