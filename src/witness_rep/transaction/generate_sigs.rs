use crate::witness_rep::{
    messages::{
        signatures, transaction_msgs
    },
};

use iota_streams::{
    core::{println, Result},
};
use identity::{
    did::MethodData,
    crypto::{KeyPair, Ed25519, Sign}
};


pub fn generate_witness_sig(
    contract: transaction_msgs::Contract,
    channel_pk_as_multibase: String,
    did_keypair: KeyPair,
    timeout: u32
) -> Result<signatures::WitnessSig> {


    let did_pk_as_multibase: String;
    let multibase_pub = MethodData::new_multibase(did_keypair.public());
    if let MethodData::PublicKeyMultibase(mbpub) = multibase_pub {
        did_pk_as_multibase = mbpub;
    }
    else {
        panic!("Could not encode public key as multibase")
    }

    // WN signs their response
    let wn_pre_sig = signatures::WitnessPreSig {
        contract: contract.clone(),
        signer_channel_pubkey: channel_pk_as_multibase.clone(),
        timeout: timeout,
    };
    println!("IMPORTANT: {:?}", wn_pre_sig);
    let wn_pre_sig_bytes = serde_json::to_string(&wn_pre_sig)?;
    let wn_sig_bytes: [u8; 64]  = Ed25519::sign(&String::into_bytes(wn_pre_sig_bytes), did_keypair.private())?;

    // WN packs the signature bytes in with the signiture message
    let wn_sig = signatures::WitnessSig {
        contract: contract.clone(),
        signer_channel_pubkey: channel_pk_as_multibase,
        timeout: timeout,
        signer_did_pubkey: did_pk_as_multibase,
        signature: wn_sig_bytes.to_vec(),
    };

    return Ok(wn_sig);
}

pub fn generate_transacting_sig(
    contract: transaction_msgs::Contract,
    channel_pk_as_multibase: String,
    did_keypair: KeyPair,
    witnesses: transaction_msgs::WitnessClients,
    witness_sigs: transaction_msgs::ArrayOfWnSignitures,
    timeout: u32
) -> Result<signatures::TransactingSig> {

    let did_pk_as_multibase: String;
    let multibase_pub = MethodData::new_multibase(did_keypair.public());
    if let MethodData::PublicKeyMultibase(mbpub) = multibase_pub {
        did_pk_as_multibase = mbpub;
    }
    else {
        panic!("Could not encode public key as multibase")
    }

    // TN_A signs the transaction
    let tn_a_tx_msg_pre_sig = signatures::TransactingPreSig {
        contract: contract.clone(),
        signer_channel_pubkey: channel_pk_as_multibase.clone(),
        witnesses: witnesses.clone(),
        wit_node_sigs: witness_sigs.clone(),
        timeout: timeout
    };
    let tn_a_tx_msg_pre_sig_bytes = serde_json::to_string(&tn_a_tx_msg_pre_sig)?;
    let tn_a_tx_msg_sig: [u8; 64]  = Ed25519::sign(&String::into_bytes(tn_a_tx_msg_pre_sig_bytes), did_keypair.private())?;

    // TN_A packs the signature bytes in with the signiture message
    let tn_a_sig = signatures::TransactingSig {
        contract: contract.clone(),
        signer_channel_pubkey: channel_pk_as_multibase.clone(),
        witnesses: witnesses,
        wit_node_sigs: witness_sigs,
        timeout: timeout,
        signer_did_pubkey: did_pk_as_multibase.clone(),
        signature: tn_a_tx_msg_sig.to_vec()
    };

    return Ok(tn_a_sig);

/*     // WN signs their response
    let wn_a_pre_sig = signatures::WitnessPreSig {
        contract: contract.clone(),
        signer_channel_pubkey: channel_pks_as_multibase[2].clone(),
        timeout: timeout,
    };
    println!("IMPORTANT: {:?}", wn_a_pre_sig);
    let wn_a_pre_sig_bytes = serde_json::to_string(&wn_a_pre_sig)?;
    let wn_a_sig_bytes: [u8; 64]  = Ed25519::sign(&String::into_bytes(wn_a_pre_sig_bytes), did_pks_keypairs[2].private())?;

    // WN packs the signature bytes in with the signiture message
    let wn_a_sig = signatures::WitnessSig {
        contract: contract.clone(),
        signer_channel_pubkey: channel_pks_as_multibase[2].clone(),
        timeout: timeout,
        signer_did_pubkey: did_pks_as_multibase[2].clone(),
        signature: wn_a_sig_bytes.to_vec(),
    };

    return Ok(wn_a_sig); */
}