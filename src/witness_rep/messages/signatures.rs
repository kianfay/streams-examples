use crate::witness_rep::messages::transaction_msgs::{Contract, WitnessClients, ArrayOfWnSignitures};
use serde::{Deserialize, Serialize};

// the signature is of the upper fields
// timeout included to give participants freedom over how long to be exposed

// contains the data being signed
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WitnessPreSig {
    pub contract: Contract,
    pub signer_channel_pubkey: String,
    pub timeout: u32,
}

// contains the data and a signature, as well the the key to verify with
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WitnessSig {
    pub contract: Contract,
    pub signer_channel_pubkey: String,
    pub timeout: u32,
    pub signer_did_pubkey: String,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransactingPreSig {
    pub contract: Contract,
    pub signer_channel_pubkey: String,
    pub witnesses: WitnessClients,
    pub wit_node_sigs: ArrayOfWnSignitures,
    pub timeout: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransactingSig {
    pub contract: Contract,
    pub signer_channel_pubkey: String,
    pub witnesses: WitnessClients,
    pub wit_node_sigs: ArrayOfWnSignitures,
    pub timeout: u32,
    pub signer_did_pubkey: String,
    pub signature: Vec<u8>,
}