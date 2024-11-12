// Import U256 from the crate's root module
use crate::U256;
// Import serialization traits from serde
use serde::{Deserialize, Serialize};
// Import digest function from sha256 crate for hashing
use sha256::digest;
// Import formatting traits for custom string representation
use std::fmt;

// Implement Display trait to enable string formatting with {}
// This converts the hash to a hexadecimal string representation
impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // {:x} formats the U256 value as lowercase hexadecimal
        write!(f, "{:x}", self.0)
    }
}

// Derive multiple traits for Hash struct:
// Hash: enables use in HashMaps/HashSets
// Clone, Copy: enables value duplication and move semantics
// Serialize, Deserialize: enables conversion to/from various formats
// Debug: enables {:?} formatting
// PartialEq, Eq: enables equality comparisons
#[derive(Hash, Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
// Tuple struct wrapping U256 to represent a 256-bit hash value
pub struct Hash(U256);

// Implementation block contains associated functions and methods
impl Hash {
    // Generic function that can hash any serializable type
    // T: generic type parameter with Serialize trait bound
    // &T: borrows data without taking ownership
    pub fn hash<T: serde::Serialize>(data: &T) -> Self {
        // Create empty byte vector for serialized data
        let mut serialized: Vec<u8> = vec![];

        // Serialize data to CBOR format using ciborium
        // if let handles potential serialization errors
        if let Err(e) = ciborium::into_writer(data, &mut serialized) {
            panic!(
                "Failed to serialize data: {:?}. \
                This should not happen",
                e
            );
        }

        // Create SHA-256 hash of serialized data
        let hash = digest(&serialized);
        // Convert hexadecimal string to bytes
        let hash_bytes = hex::decode(hash).unwrap();
        // Convert byte vector to fixed-size array
        let hash_array: [u8; 32] = hash_bytes.as_slice().try_into().unwrap();
        // Create new Hash instance from byte array
        Hash(U256::from(hash_array))
    }

    // Check if hash value is less than or equal to target
    // Used for proof-of-work verification
    pub fn matches_target(&self, target: U256) -> bool {
        self.0 <= target
    }

    // Create a Hash instance with value zero
    // Useful for initialization and testing
    pub fn zero() -> Self {
        Hash(U256::zero())
    }

    // Convert hash to little-endian byte array
    // Used for cryptographic operations
    pub fn as_bytes(&self) -> [u8; 32] {
        // Create zeroed byte vector with 32-byte capacity
        let mut bytes: Vec<u8> = vec![0; 32];
        // Fill vector with hash value in little-endian order
        self.0.to_little_endian(&mut bytes);
        // Convert vector to fixed-size array
        bytes.as_slice().try_into().unwrap()
    }
}

