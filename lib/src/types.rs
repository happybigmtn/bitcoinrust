use crate::crypto::{PublicKey, Signature};
use crate::error::{BtcError, Result};
use crate::sha256::Hash;
use crate::util::MerkleRoot;
use crate::U256;
use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
// Core blockchain data structures
// Each structure implements Serialize/Deserialize for persistence
// Clone for copying, Debug for development visibility

/// BlockHeader contains metadata about a block
/// - timestamp: When block was created
/// - nonce: Proof-of-work solution
/// - prev_block_hash: Links to previous block
/// - merkle_root: Transaction commitment
/// - target: Mining difficulty
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BlockHeader {
    pub timestamp: DateTime<Utc>,
    pub nonce: u64,
    pub prev_block_hash: Hash,
    pub merkle_root: MerkleRoot,
    pub target: U256,
}

impl BlockHeader {
    pub fn new(
        timestamp: DateTime<Utc>,
        nonce: u64,
        prev_block_hash: Hash,
        merkle_root: MerkleRoot,
        target: U256,
    ) -> Self {
        BlockHeader {
            merkle_root,
            timestamp,
            nonce,
            prev_block_hash,
            target,
        }
    }
    pub fn hash(&self) -> Hash {
        Hash::hash(self)
    }
    pub fn mine(&mut self, steps: usize) -> bool {
        // if the block already matches target, return early
        if self.hash().matches_target(self.target) {
            return true;
        }
        for _ in 0..steps {
            if let Some(new_nonce) = self.nonce.checked_add(1) {
                self.nonce = new_nonce;
            } else {
                self.nonce = 0;
                self.timestamp = Utc::now()
            }
            if self.hash().matches_target(self.target) {
                return true;
            }
        }
        false
    }
}

/// Transaction represents value transfer between parties
/// - inputs: Sources of value (previous transaction outputs)
/// - outputs: New value destinations
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
}

/// TransactionInput spends a previous output
/// - prev_transaction_output_hash: Reference to output being spent
/// - signature: Cryptographic proof of ownership
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransactionInput {
    pub prev_transaction_output_hash: Hash,
    pub signature: Signature,
}

/// TransactionOutput creates new spendable value
/// - value: Amount of currency
/// - unique_id: Unique identifier for this output
/// - pubkey: Owner's public key (recipient)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransactionOutput {
    pub value: u64,
    pub unique_id: Uuid,
    pub pubkey: PublicKey,
}

impl TransactionOutput {
    pub fn hash(&self) -> Hash {
        Hash::hash(self)
    }
}

impl Transaction {
    pub fn new(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Self {
        Transaction { inputs, outputs }
    }
    pub fn hash(&self) -> Hash {
        Hash::hash(self)
    }
}

/// Block groups transactions with their metadata
/// - header: Block metadata
/// - transactions: List of included transactions
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Block {
            header,
            transactions,
        }
    }
    pub fn hash(&self) -> Hash {
        Hash::hash(self)
    }
    // Verify coinbase transaction
    pub fn verify_coinbase_transaction(
        &self,
        predicted_block_height: u64,
        utxos: &HashMap<Hash, TransactionOutput>,
    ) -> Result<()> {
        // coinbase tx is the first transaction in the block
        let coinbase_transaction = &self.transactions[0];
        if coinbase_transaction.inputs.len() != 0 {
            return Err(BtcError::InvalidTransaction);
        }
        if coinbase_transaction.outputs.len() == 0 {
            return Err(BtcError::InvalidTransaction);
        }
        let miner_fees = self.calculate_miner_fees(utxos)?;
        let block_reward = crate::INITIAL_REWARD * 10u64.pow(8)
            / 2u64.pow((predicted_block_height / crate::HALVING_INTERVAL) as u32);
        let total_coinbase_outputs: u64 = coinbase_transaction
            .outputs
            .iter()
            .map(|output| output.value)
            .sum();
        if total_coinbase_outputs != block_reward + miner_fees {
            return Err(BtcError::InvalidTransaction);
        }
        Ok(())
    }

    pub fn calculate_miner_fees(&self, utxos: &HashMap<Hash, TransactionOutput>) -> Result<u64> {
        let mut inputs: HashMap<Hash, TransactionOutput> = HashMap::new();
        let mut outputs: HashMap<Hash, TransactionOutput> = HashMap::new();
        // Check every transaction after coinbase
        for transaction in self.transactions.iter().skip(1) {
            for input in &transaction.inputs {
                // inputs do not contain
                // the values of the outputs
                // so we need to match inputs
                // to outputs
                let prev_output = utxos.get(&input.prev_transaction_output_hash);
                if prev_output.is_none() {
                    return Err(BtcError::InvalidTransaction);
                }
                let prev_output = prev_output.unwrap();
                if inputs.contains_key(&input.prev_transaction_output_hash) {
                    return Err(BtcError::InvalidTransaction);
                }
                inputs.insert(input.prev_transaction_output_hash, prev_output.clone());
            }
            for output in &transaction.outputs {
                if outputs.contains_key(&output.hash()) {
                    return Err(BtcError::InvalidTransaction);
                }
                outputs.insert(output.hash(), output.clone());
            }
        }
        let input_value: u64 = inputs.values().map(|output| output.value).sum();
        let output_value: u64 = outputs.values().map(|output| output.value).sum();
        Ok(input_value - output_value)
    }
    // Method on Block struct that verifies all transactions in a block
    // Takes a reference to UTXO set and returns Result (Ok or Err)
    pub fn verify_transactions(
        &self,
        predicted_block_height: u64,
        utxos: &HashMap<Hash, TransactionOutput>,
    ) -> Result<()> {
        // Create mutable HashMap to track inputs used in this block
        // This prevents double-spending within the same block
        let mut inputs: HashMap<Hash, TransactionOutput> = HashMap::new();

        // Reject blocks with no transactions
        // self.transactions accesses the Vec<Transaction> field of Block
        // .is_empty() is a Vec method that returns true if length is 0
        if self.transactions.is_empty() {
            return Err(BtcError::InvalidTransaction);
        }

        self.verify_coinbase_transaction(predicted_block_height, utxos)?;
        // Iterate over each transaction in the block
        // &self.transactions creates a reference to avoid moving ownership
        for transaction in self.transactions.iter().skip(1) {
            // Running totals for transaction validation
            // mut allows these values to be modified
            let mut input_value = 0;
            let mut output_value = 0;

            // Check each input (source of funds) in the transaction
            for input in &transaction.inputs {
                // Look up the referenced output in the UTXO set
                // .get() returns an Option<&TransactionOutput>
                let prev_output = utxos.get(&input.prev_transaction_output_hash);

                // If the UTXO doesn't exist, transaction is invalid
                // .is_none() checks if Option is None
                if prev_output.is_none() {
                    return Err(BtcError::InvalidTransaction);
                }

                // Unwrap the Option to get the TransactionOutput
                // .unwrap() is safe here because we checked is_none()
                let prev_output = prev_output.unwrap();

                // Check if this input was already used in this block
                // .contains_key() checks if key exists in HashMap
                if inputs.contains_key(&input.prev_transaction_output_hash) {
                    return Err(BtcError::InvalidTransaction);
                }

                // Verify cryptographic signature
                // .verify() checks if signature is valid for this hash and pubkey
                // The '!' negates the result - if verify returns false, this is true
                if !input
                    .signature
                    .verify(&input.prev_transaction_output_hash, &prev_output.pubkey)
                {
                    return Err(BtcError::InvalidSignature);
                }

                // Add this input's value to running total
                // += is compound assignment operator (input_value = input_value + prev_output.value)
                input_value += prev_output.value;

                // Mark this input as used in this block
                // .insert() adds key-value pair to HashMap
                // .clone() creates a copy of prev_output
                inputs.insert(input.prev_transaction_output_hash, prev_output.clone());
            }

            // Sum up all output values
            // Iterate over references to outputs to avoid moving
            for output in &transaction.outputs {
                output_value += output.value;
            }

            // Ensure inputs >= outputs (can't spend more than you have)
            // The difference between input_value and output_value is the transaction fee
            if input_value < output_value {
                return Err(BtcError::InvalidTransaction);
            }
        }

        // If we get here, all transactions are valid
        // Ok(()) is the unit value wrapped in Ok variant of Result
        Ok(())
    }
}
/// Blockchain maintains the full chain state
/// - utxos: Set of unspent transaction outputs
/// - blocks: Ordered list of validated blocks
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Blockchain {
    utxos: HashMap<Hash, TransactionOutput>,
    target: U256,
    blocks: Vec<Block>,
    #[serde(default, skip_serializing)]
    mempool: Vec<Transaction>,
}

impl Blockchain {
    pub fn new() -> Self {
        Blockchain {
            utxos: HashMap::new(),
            target: crate::MIN_TARGET,
            blocks: vec![],
            mempool: vec![],
        }
    }
    pub fn mempool(&self) -> &[Transaction] {
        &self.mempool
    }
    pub fn utxos(&self) -> &HashMap<Hash, TransactionOutput> {
        &self.utxos
    }
    pub fn target(&self) -> U256 {
        self.target
    }
    pub fn blocks(&self) -> impl Iterator<Item = &Block> {
        self.blocks.iter()
    }
    pub fn block_height(&self) -> u64 {
        self.blocks.len() as u64
    }
    pub fn add_to_mempool(&mut self, transaction: Transaction) -> Result<()> {
        let mut known_inputs = HashSet::new();
        for input in &transaction.inputs {
            if !self.utxos.contains_key(&input.prev_transaction_output_hash) {
                return Err(BtcError::InvalidTransaction);
            }
            if known_inputs.contains(&input.prev_transaction_output_hash) {
                return Err(BtcError::InvalidTransaction);
            }
            known_inputs.insert(input.prev_transaction_output_hash);
        }
        let all_inputs = transaction
            .inputs
            .iter()
            .map(|input| {
                self.utxos
                    .get(&input.prev_transaction_output_hash)
                    .expect("BUG")
                    .value
            })
            .sum::<u64>();
        let all_outputs = transaction.outputs.iter().map(|output| output.value).sum();
        if all_inputs < all_outputs {
            return Err(BtcError::InvalidTransaction);
        }
        self.mempool.push(transaction);
        self.mempool.sort_by_key(|transaction| {
            let all_inputs = transaction
                .inputs
                .iter()
                .map(|input| {
                    self.utxos
                        .get(&input.prev_transaction_output_hash)
                        .expect("BUG: impossible")
                        .value
                })
                .sum::<u64>();
            let all_outputs: u64 = transaction.outputs.iter().map(|output| output.value).sum();
            let miner_fee = all_inputs - all_outputs;
            miner_fee
        });
        Ok(())
    }
    pub fn add_block(&mut self, block: Block) -> Result<()> {
        if self.blocks.is_empty() {
            if block.header.prev_block_hash != Hash::zero() {
                println!("zero hash");
                return Err(BtcError::InvalidBlock);
            }
        } else {
            let last_block = self.blocks.last().unwrap();
            if block.header.prev_block_hash != last_block.hash() {
                println!("prev hash is wrong");
                return Err(BtcError::InvalidBlock);
            }
            if !block.header.hash().matches_target(block.header.target) {
                println!("does not match target");
                return Err(BtcError::InvalidBlock);
            }
            let calculated_merkle_root = MerkleRoot::calculate(&block.transactions);
            if calculated_merkle_root != block.header.merkle_root {
                println!("invalid merkle root");
                return Err(BtcError::InvalidMerkleRoot);
            }
            if block.header.timestamp <= last_block.header.timestamp {
                return Err(BtcError::InvalidBlock);
            }
            block.verify_transactions(self.block_height(), &self.utxos)?;
        }
        let block_transactions: HashSet<_> =
            block.transactions.iter().map(|tx| tx.hash()).collect();
        self.mempool
            .retain(|tx| !block_transactions.contains(&tx.hash()));
        self.blocks.push(block);
        self.try_adjust_target();
        Ok(())
    }
    pub fn rebuild_utxos(&mut self) {
        for block in &self.blocks {
            for transaction in &block.transactions {
                for input in &transaction.inputs {
                    self.utxos.remove(&input.prev_transaction_output_hash);
                }
                for output in transaction.outputs.iter() {
                    self.utxos.insert(transaction.hash(), output.clone());
                }
            }
        }
    }
    pub fn try_adjust_target(&mut self) {
        if self.blocks.is_empty() {
            return;
        }
        if self.blocks.len() % crate::DIFFICULTY_UPDATE_INTERVAL as usize != 0 {
            return;
        }
        // measure the time it took to mine the last
        // crate::DIFFICULTY_UPDATE_INTERVAL blocks
        // with chrono
        let start_time = self.blocks
            [self.blocks.len() - crate::DIFFICULTY_UPDATE_INTERVAL as usize]
            .header
            .timestamp;
        let end_time = self.blocks.last().unwrap().header.timestamp;
        let time_diff = end_time - start_time;
        // convert time_diff to seconds
        let time_diff_seconds = time_diff.num_seconds();
        // calculate the ideal number of seconds
        let target_seconds = crate::IDEAL_BLOCK_TIME * crate::DIFFICULTY_UPDATE_INTERVAL;
        // multiply the current target by actual time divided by ideal time
        let new_target = BigDecimal::parse_bytes(&self.target.to_string().as_bytes(), 10)
            .expect("BUG")
            * (BigDecimal::from(time_diff_seconds) / BigDecimal::from(target_seconds));
        // clamp new_target to be within the range of
        // 4 * self.target and self.target / 4
        let new_target_str = new_target
            .to_string()
            .split('.')
            .next()
            .expect("BUG")
            .to_owned();
        let new_target: U256 = U256::from_str_radix(&new_target_str, 10).expect("BUG");
        let new_target = if new_target < self.target / 4 {
            self.target / 4
        } else if new_target > self.target * 4 {
            self.target * 4
        } else {
            new_target
        };
        // if the new target is more than the minimum target,
        // set it to the minimum target
        self.target = new_target.min(crate::MIN_TARGET);
    }
}
