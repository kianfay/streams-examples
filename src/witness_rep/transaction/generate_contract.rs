use crate::witness_rep::{
    messages::transaction_msgs,
    transaction::transaction::ParticipantIdentity,
};

use iota_streams::{
    core::Result
};
use identity::{
    did::MethodData,
    crypto::KeyPair
};

pub fn generate_contract(transacting_ids: &mut Vec<ParticipantIdentity>) -> Result<transaction_msgs::Contract> {
    // get the did pubkeys from the ids
    let did_pubkeys_res : Result<Vec<String>> = transacting_ids
        .iter()
        .map(|ParticipantIdentity {
            channel_client: _,
            did_key
        }| {
            let kp = KeyPair::try_from_ed25519_bytes(did_key)?;
            let multibase_pub = MethodData::new_multibase(kp.public());

            if let MethodData::PublicKeyMultibase(mbpub) = multibase_pub {
                return Ok(mbpub);
            }
            else {
                return Ok(String::default());
            }
        })
        .collect();
    let did_pubkeys = did_pubkeys_res?;
    
    // generate the contract
    let contract_hardcoded = transaction_msgs::Contract {
        contract_definition: String::from("tn_b allows tn_a to enter in front of it in the lane tn_b is in"),               
        participants: transaction_msgs::TransactingClients(
            Vec::from([did_pubkeys[0].clone(), did_pubkeys[1].clone()])
        ),      
        time: 1643572739,
        location: ((53, 20, 27.036),(6, 15, 2.695)),
    };

    return Ok(contract_hardcoded);
}