use crate::witness_rep::messages::transaction_msgs::{Contract, WitnessClients};
use serde::{Deserialize, Serialize};

// the signature is of the upper fields
// timeout included to give participants freedom over how long to be exposed

#[derive(Serialize, Deserialize)]
pub struct WitnessPreSig {
    pub contract: Contract,
    pub timeout: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WitnessSig {
    pub contract: Contract,
    pub timeout: u32,
    pub signature: Vec<u8>,
}

pub struct TransactingPreSig {
    pub contract: Contract,
    pub witnesses: WitnessClients,
    pub timeout: u32,
}

pub struct TransactingSig {
    pub contract: Contract,
    pub witnesses: WitnessClients,
    pub timeout: u32,
    pub signature: Vec<u8>,
}