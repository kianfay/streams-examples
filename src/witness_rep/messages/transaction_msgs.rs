use serde::{Deserialize, Serialize};

//////
////	STRUCTURES
//////

#[derive(Serialize, Deserialize, Clone)]
pub struct TransactionMsgPreSig {
    pub contract: Contract,
	pub witnesses: WitnessClients,
    pub wit_node_sigs: ArrayOfSignitures,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TransactionMsg {
    pub contract: Contract,
	pub witnesses: WitnessClients,
    pub wit_node_sigs: ArrayOfSignitures,
	pub tx_client_sigs: ArrayOfSignitures,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Contract {
    pub contract_definition: String,               
	pub participants: TransactingClients,          
	pub time: UnixTimestamp,
	pub location: CoordinateDMSFormat,
}

// an array of bytes representing the pubkey of the participant
#[derive(Serialize, Deserialize, Clone)]
pub struct TransactingClients   (pub Vec<PublicKey>);
#[derive(Serialize, Deserialize, Clone)]
pub struct WitnessClients       (pub Vec<PublicKey>);

pub type PublicKey = String;

// u64 used for timestamp as u32 runs out in 2038 (2147483647 as unixtime)
pub type UnixTimestamp = u64;

// CoordinateDMSFormat(North Ordinate, West Ordinate)
pub type CoordinateDMSFormat = (Ordinate,Ordinate);
pub type Ordinate = (u16,u16,f32);

// signitures are also simply arrays of bytes
#[derive(Serialize, Deserialize, Clone)]
pub struct Signature(pub Vec<u8>);
#[derive(Serialize, Deserialize, Clone)]
pub struct ArrayOfSignitures(pub Vec<Signature>);

//////
////	UTILITY FUNCTIONS
//////

