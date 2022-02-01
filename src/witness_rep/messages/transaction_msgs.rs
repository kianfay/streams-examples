use identity::crypto::PublicKey;

//////
////	STRUCTURES
//////

pub struct TransactionMsg {
    contract: Contract,
	witnesses: WitnessClients,
    wit_node_sigs: ArrayOfSignitures,
	tx_client_sigs: ArrayOfSignitures,
}

pub struct Contract {
    contract_definition: String,               
	participants: TransactingClients,          
	time: UnixTimestamp,
	location: CoordinateDMSFormat,
}

// an array of bytes representing the pubkey of the participant
pub struct TransactingClients   (pub Vec<PublicKey>);
pub struct WitnessClients       (pub Vec<PublicKey>);

// u64 used for timestamp as u32 runs out in 2038 (2147483647 as unixtime)
pub type UnixTimestamp = u64;

// CoordinateDMSFormat(North Ordinate, West Ordinate)
pub type CoordinateDMSFormat = (Ordinate,Ordinate);
pub type Ordinate = (u16,u16,f32);

// signitures are also simply arrays of bytes
pub struct Signiture(Vec<u8>);
pub struct ArrayOfSignitures(Vec<u8>);

//////
////	UTILITY FUNCTIONS
//////

