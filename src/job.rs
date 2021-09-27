// rtj provides a generic job execution framework in Rust
// Copyright 2021 Anthony Martinez
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/// The core trait [`Job`] providing required methods to user-defined data types for
/// orchestrating task execution.
///
/// It is left to the implementor to ensure these methods do not panic or that errors
/// are handled as they see fit.
pub trait Job {
    fn encode(&self) -> Vec<u8>;
    fn decode(input: &[u8]) -> Self;
    fn ack(&self) -> Vec<u8>;
    fn run(&self) -> std::result::Result<(), Box<dyn std::error::Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

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
            let ack_string = format!("Hello from {}, aged {}", self.name, self.age);
            Vec::from(ack_string)
        }

        fn run(&self) -> std::result::Result<(), Box<dyn std::error::Error>> {
            self.ack();
            Ok(())
        }
    }

    #[test]
    fn test_job_encode_decode() {
        let hello = Hello {
            name: "Anthony J. Martinez".to_owned(),
            age: 38,
        };

        let encoded = hello.encode();
        let decoded = Hello::decode(&encoded);

        assert_eq!(hello, decoded)
    }

    #[test]
    fn test_job_ack() {
        let hello = Hello {
            name: "Anthony J. Martinez".to_owned(),
            age: 38,
        };

        let hello_vec = hello.ack();

        assert_eq!(
            hello_vec,
            Vec::from("Hello from Anthony J. Martinez, aged 38")
        )
    }

    #[test]
    fn test_job_run() {
        let hello = Hello {
            name: "Anthony J. Martinez".to_owned(),
            age: 38,
        };

        assert!(hello.run().is_ok())
    }
}
