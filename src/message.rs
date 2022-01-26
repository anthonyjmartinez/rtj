// rtj provides a generic job execution framework in Rust
// Copyright 2021-2022 Anthony Martinez
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::*;

/// Provides a container for [`Header`] and Serialized and/or Encrypted [`Job`] payloads.
#[derive(Default, Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Message {
    pub header: Header,
    pub payload: Vec<u8>,
}

impl Message {
    /// Creates a new [`Message`] with default values
    pub fn new() -> Message {
        Message::default()
    }

    /// Sets the [`Message`] header field
    ///
    /// This method can only be called after [`Message::set_payload`]
    /// as the header itself contains the size of the payload in bytes.
    ///
    /// Public key bytes to be sent in the [`Header`] must be the public
    /// part of the sender's [`SecretKey`].
    pub fn set_header<T: Into<u8>, U: Into<[u8; 32]>, V: RngCore + CryptoRng>(
        mut self,
        msgtype: T,
        pubkey: U,
        csprng: &mut V,
    ) -> Result<Message> {
        if self.payload.is_empty() {
            Err(RtjError::InvalidOperation(
                "empty payload. cannot set header".to_owned(),
            ))
        } else {
            let header = Header::new()
                .set_msgtype(msgtype)
                .set_psize(self.payload.len() as u32)
                .set_pubkey(pubkey.into())
                .set_nonce(csprng)?;

            self.header = header;
            Ok(self)
        }
    }

    /// Sets the [`Message`] payload field.
    pub fn set_payload<T: Job>(mut self, payload: &T) -> Message {
        self.payload = payload.encode();
        self
    }

    /// Encrypts and resets the [`Message`] payload field using the specified [`PublicKey`]
    /// of the recipient and [`SecretKey`] of the sender.
    ///
    /// The [`Header`] is updated to:
    /// - Reflect the new payload length
    /// - Set the encrypted flag
    ///
    /// Payload is encrypted for the given pubkey.
    /// Encryption is done using [`crypto_box`] in its default configuration.
    pub fn encrypt(mut self, public: PublicKey, secret: SecretKey) -> Result<Message> {
        if !self.header.encrypted {
            let mut msg_box = crypto_box::Box::new(&public, &secret);
            let nonce: GenericArray<u8, U24> = self.header.nonce.into();
            let encrypted_payload = msg_box.encrypt(&nonce, &self.payload[..])?;
            self.payload = encrypted_payload;
            self.header = self.header.set_encrypted(true);
            self.header = self.header.set_psize(self.payload.len() as u32);
            Ok(self)
        } else {
            Err(RtjError::InvalidOperation(
                "encrypt called on previously encrypted payload".to_owned(),
            ))
        }
    }

    /// Decrypts and resets the [`Message`] payload using the specified [`SecretKey`]
    ///
    /// Payload is decrypted for the pubkey specified in the [`Message`] header.
    /// Decryption is done using [`crypto_box`] in its default configuration.
    pub fn decrypt(mut self, secret: SecretKey) -> Result<Message> {
        if self.header.encrypted {
            let mut msg_box = crypto_box::Box::new(&self.header.pubkey.into(), &secret);
            let nonce: GenericArray<u8, U24> = self.header.nonce.into();
            let decrypted_payload = msg_box.decrypt(&nonce, &self.payload[..])?;
            self.payload = decrypted_payload;
            Ok(self)
        } else {
            Err(RtjError::InvalidOperation(
                "decrypt called on plaintext message".to_owned(),
            ))
        }
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
    fn test_message_new() {
        let msg = Message::new();
        let ref_msg = Message {
            header: Header::new(),
            payload: Vec::default(),
        };

        assert_eq!(msg, ref_msg)
    }

    #[test]
    fn test_message_set_payload() {
        let hello = Hello {
            name: "Anthony J. Martinez".to_owned(),
            age: 38,
        };

        let msg = Message::new().set_payload(&hello);

        assert_eq!(msg.payload, hello.encode())
    }

    #[test]
    fn test_message_set_header() {
        let mut rng = rand::thread_rng();
        let secret_key = crypto_box::SecretKey::generate(&mut rng);
        let pubkey = secret_key.public_key().as_bytes().to_owned();
        let hello = Hello {
            name: "Anthony J. Martinez".to_owned(),
            age: 38,
        };

        let msg = Message::new().set_payload(&hello);

        assert!(msg.set_header(MsgType::Hello, pubkey, &mut rng).is_ok())
    }

    #[test]
    fn test_message_encrypt() {
        let mut rng = rand::thread_rng();
        let bob_key = crypto_box::SecretKey::generate(&mut rng);
        let bob_pubkey = bob_key.public_key().as_bytes().to_owned();
        let alice_key = crypto_box::SecretKey::generate(&mut rng);
        let alice_pubkey = alice_key.public_key().as_bytes().to_owned();

        let hello = Hello {
            name: "Anthony J. Martinez".to_owned(),
            age: 38,
        };

        let msg = Message::new()
            .set_payload(&hello)
            .set_header(MsgType::Hello, bob_pubkey, &mut rng)
            .unwrap()
            .encrypt(PublicKey::from(alice_pubkey), bob_key)
            .unwrap();

        assert!(msg.header.encrypted)
    }

    #[test]
    fn test_message_decrypt() {
        let mut rng = rand::thread_rng();
        let bob_key = crypto_box::SecretKey::generate(&mut rng);
        let bob_pubkey = bob_key.public_key().as_bytes().to_owned();
        let alice_key = crypto_box::SecretKey::generate(&mut rng);
        let alice_pubkey = alice_key.public_key().as_bytes().to_owned();

        let hello = Hello {
            name: "Anthony J. Martinez".to_owned(),
            age: 38,
        };

        let encrypted_msg = Message::new()
            .set_payload(&hello)
            .set_header(MsgType::Hello, bob_pubkey, &mut rng)
            .unwrap()
            .encrypt(PublicKey::from(alice_pubkey), bob_key)
            .unwrap();

        let decrypted_msg = encrypted_msg.decrypt(alice_key);
        assert!(decrypted_msg.is_ok())
    }
}
