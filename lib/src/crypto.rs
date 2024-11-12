// Import specific items from the ecdsa crate
// The 'use' keyword brings symbols into scope
// The curly braces group multiple imports from the same path
// 'as' creates an alias to avoid name conflicts
use ecdsa::{
    signature::{Signer, Verifier},
    Signature as ECDSASignature,
    SigningKey,
    VerifyingKey
};
use k256::Secp256k1;  // Single import for the Secp256k1 curve implementation
use serde::{Deserialize, Serialize};  // Traits for serialization/deserialization
use crate::sha256::Hash;  // Add Hash type import

// Derive macro applies multiple trait implementations automatically
// Debug: enables {:?} formatting
// Serialize/Deserialize: enables serde conversion
// Clone: enables .clone() method
#[derive(Debug, Serialize, Deserialize, Clone)]
// 'pub' makes the struct accessible from other modules
// Tuple struct with single field - wrapper around ECDSASignature
pub struct Signature(pub ECDSASignature<Secp256k1>);

// Implementation block contains associated functions and methods
impl Signature {
    // Associated function: called as Signature::sign_output() rather than on an instance
    // &Hash: reference to prevent taking ownership of the hash
    // &PrivateKey: reference to the key to allow reuse
    // -> Self: returns a new Signature instance
    pub fn sign_output(output_hash: &Hash, private_key: &PrivateKey) -> Self {
        // .0 accesses the inner SigningKey from the tuple struct
        // & creates a reference to the inner key
        let signing_key = &private_key.0;
        
        // sign() is from the Signer trait
        // as_bytes() converts the hash to a byte slice (&[u8])
        let signature = signing_key.sign(&output_hash.as_bytes());
        
        // Wrap the ECDSASignature in our custom Signature type
        // No semicolon = implicit return expression
        Signature(signature)
    }

    // Method takes &self (reference to instance)
    // Returns bool indicating verification success
    pub fn verify(&self, output_hash: &Hash, public_key: &PublicKey) -> bool {
        public_key
            .0  // Access inner VerifyingKey from PublicKey
            .verify(
                &output_hash.as_bytes(),  // Convert hash to bytes for verification
                &self.0  // Reference to inner ECDSASignature
            )
            .is_ok()  // Convert Result<(), Error> to bool: Ok(_) => true, Err(_) => false
    }
}

// Additional derives: PartialEq, Eq for equality comparisons
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PublicKey(pub VerifyingKey<Secp256k1>);

// Custom serialization needed because SigningKey doesn't implement Serialize/Deserialize
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrivateKey(
    // serde attribute directs serialization to custom module
    // This allows us to define how the SigningKey is converted to/from bytes
    #[serde(with = "signkey_serde")] 
    pub SigningKey<Secp256k1>
);

// Internal module for custom serialization
mod signkey_serde {
    use serde::Deserialize;  // Local import scope

    // Generic serialization function
    // S: generic type parameter with Serializer trait bound
    pub fn serialize<S>(
        key: &super::SigningKey<super::Secp256k1>,  // super:: refers to parent module
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&key.to_bytes())
    }

    // Generic deserialization function
    // 'de lifetime ensures deserializer lives as long as deserialized data
    // D: generic deserializer type that must implement Deserializer trait
    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<super::SigningKey<super::Secp256k1>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize bytes first, then convert to SigningKey
        // ?: operator unwraps Result or returns early with error
        let bytes: Vec<u8> = Vec::<u8>::deserialize(deserializer)?;
        
        // from_slice creates SigningKey from bytes
        // unwrap() here assumes valid key data - could panic in production
        Ok(super::SigningKey::from_slice(&bytes).unwrap())
    }
}

impl PrivateKey {
    // Constructor that requires no parameters
    pub fn new_key() -> Self {
        // thread_rng(): thread-local random number generator
        // random(): generates cryptographically secure random key
        PrivateKey(SigningKey::random(&mut rand::thread_rng()))
    }

    // &self: borrows PrivateKey instance without taking ownership
    pub fn public_key(&self) -> PublicKey {
        // verifying_key(): derives public key from private key
        // clone(): creates owned copy of VerifyingKey
        PublicKey(self.0.verifying_key().clone())
    }
}