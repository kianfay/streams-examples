use crate::witness_rep::messages::transaction_msgs::{Contract, WitnessClients};

// the signature is of the upper fields
// timeout included to give participants freedom over how long to be exposed
pub struct WitnessPreSig {
    contract: Contract,
    timeout: u32,
}

pub struct WitnessSig {
    contract: Contract,
    timeout: u32,
    signature: Vec<u8>,
}

pub struct TransactingPreSig {
    contract: Contract,
    witnesses: WitnessClients,
    timeout: u32,
}

pub struct TransactingSig {
    contract: Contract,
    witnesses: WitnessClients,
    timeout: u32,
    signature: Vec<u8>,
}