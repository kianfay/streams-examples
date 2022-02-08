use identity::{
    crypto::{Ed25519, Verify, KeyPair, Sign},
    did::MethodData,
};
use iota_streams::{
    app::transport::tangle::{client::Client, TangleAddress},
    app_channels::api::tangle::{
        Address, Author, Bytes, ChannelType, MessageContent, Subscriber,
        UnwrappedMessage, PublicKey
    },
    core::{println, Result},
};
use crate::witness_rep::utility::extract_msgs;

use core::str::FromStr;

use crate::witness_rep::messages::*;
use crate::witness_rep::iota_did::*;
use crate::witness_rep::messages::signatures;
use crate::witness_rep::messages::transaction_msgs::{
    TransactionMsg, ArrayOfTxSignitures, ArrayOfWnSignitures 
};

pub async fn verify_tx(node_url: &str, ann_msg: String) -> Result<bool> {
    let client = Client::new_from_url(node_url);
    let mut reader = Subscriber::new("Transacting Node A", client.clone());

    let ann_address = Address::from_str(&ann_msg)?;
    reader.receive_announcement(&ann_address).await?;

    let mut retrieved = reader.fetch_all_next_msgs().await;
    println!("\nAuthor found {} messages", retrieved.len());

    let msgs = extract_msgs::extract_msg(retrieved);
    println!("{:?}", msgs);

    // parse the string into the TransactionMsg format
    let msg1 : TransactionMsg = serde_json::from_str(msgs[0].as_str())?;
    println!("{:?}", msg1);
    let verified = verify_msg(msg1);
    println!("{}", verified);

    return Ok(false);
}

pub fn verify_msg(tx_msg: TransactionMsg) -> bool {

    let (ArrayOfWnSignitures(wit_sigs), ArrayOfTxSignitures(tn_sigs)) = get_sigs(tx_msg);
    
    for ws in wit_sigs.iter() {
        if verify_witness_sig(ws.clone()) == false {
            return false;
        }
    }
    for ts in tn_sigs.iter() {
        if verify_tx_sig(ts.clone()) == false {
            return false;
        }
    }

    return true;
}

pub fn get_sigs(tx: TransactionMsg) -> (ArrayOfWnSignitures,ArrayOfTxSignitures) {
    match tx {
        TransactionMsg {
            contract: _,
            witnesses: _,
            wit_node_sigs,
            tx_client_sigs,
        } => return (wit_node_sigs, tx_client_sigs)
    };
}

pub fn verify_witness_sig(sig: signatures::WitnessSig) -> bool{
    match sig {
        signatures::WitnessSig {
            contract,
            timeout,
            signer_pubkey,
            signature,
        } => {
            let pre_sig = signatures::WitnessPreSig {
                contract,
                timeout,
            };
            println!("IMPORTANT: {:?}", pre_sig);

            let pre_sig = serde_json::to_string(&pre_sig).unwrap();

            let sig_unsigned = Ed25519::verify(&String::into_bytes(pre_sig), &signature, &signer_pubkey);
            if let Ok(()) = sig_unsigned {
                return true;
            } else {
                panic!("Signature verification failed")
            }
        }
    }
}

pub fn verify_tx_sig(sig: signatures::TransactingSig) -> bool{
    match sig {
        signatures::TransactingSig {
            contract,
            witnesses,
            wit_node_sigs,
            timeout,
            signer_pubkey,
            signature,
        } => {
            let pre_sig = signatures::TransactingPreSig {
                contract,
                witnesses,
                wit_node_sigs,
                timeout,
            };

            let pre_sig = serde_json::to_string(&pre_sig).unwrap();

            let sig_unsigned = Ed25519::verify(pre_sig.as_bytes(), &signature, &signer_pubkey);
            if let Ok(()) = sig_unsigned {
                return true;
            } else {
                panic!("Signature verification failed")
            }
        }
    }
}

pub fn testing_sigs() -> Result<bool>{

    let (kp, (pubk, sec)) = create_and_upload_did::gen_iota_keypair();
    let multibase_pkey = MethodData::new_multibase(kp.public());
    println!("{:?}", multibase_pkey);
    let mut pupk2 = String::from(" ");
    if let MethodData::PublicKeyMultibase(mbpub) = multibase_pkey {
        println!("here");
        pupk2 = mbpub;
    }

    let contract_by_tn_a = transaction_msgs::Contract {
        contract_definition: String::from("tn_b allows tn_a to enter in front of it in the lane tn_b is in"),               
        participants: transaction_msgs::TransactingClients(
            Vec::from(["pub1".to_string(), "pub2".to_string()])
        ),      
        time: 1643572739,
        location: ((53, 20, 27.036),(6, 15, 2.695)),
    };
    let wn_a_pre_sig = signatures::WitnessPreSig {
        contract: contract_by_tn_a.clone(),
        timeout: 5,
    };
    println!("IMPORTANT: {:?}", wn_a_pre_sig);

    let test = serde_json::to_string(&wn_a_pre_sig)?;
    let sig_bytes: [u8; 64]  = Ed25519::sign(test.as_bytes(), &sec)?;

    let rebuilt_pre_sig: signatures::WitnessPreSig = serde_json::from_str(&test)?;
    let test2 = serde_json::to_string(&rebuilt_pre_sig)?;

    let verified = Ed25519::verify(test2.as_bytes(), &sig_bytes, &pubk);
    if let Ok(()) = verified {
        println!("true");
    } else {
        panic!("Signature verification failed")
    }

    return Ok(true);

}