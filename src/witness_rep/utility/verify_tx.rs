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
    core::{println, Result, Errors::BadTransactionTag},
};
use crate::witness_rep::utility::extract_msgs;

use core::str::FromStr;

use crate::witness_rep::messages::*;
use crate::witness_rep::iota_did::*;
use crate::witness_rep::messages::signatures;
use crate::witness_rep::messages::witness_msgs::WitnessStatement;
use crate::witness_rep::messages::transaction_msgs::{
    TransactionMsg, ArrayOfTxSignitures, ArrayOfWnSignitures 
};

pub async fn verify_txs(node_url: &str, ann_msg: String) -> Result<bool> {
    
    // build another client to read the tangle with
    let client = Client::new_from_url(node_url);
    let mut reader = Subscriber::new("Transacting Node A", client.clone());

    // process the address string
    let ann_address = Address::from_str(&ann_msg)?;
    reader.receive_announcement(&ann_address).await?;

    // fetch messages from address, and extract their payloads
    let retrieved = reader.fetch_all_next_msgs().await;
    println!("\nAuthor found {} messages", retrieved.len());
    let msgs = extract_msgs::extract_msg(retrieved);
    //println!("{:?}", msgs);

    // parse the string into the TransactionMsg/WitnessStatement/CompensationMsg format and check if valid

    let mut valid_pks: Vec<PublickeyOwner> = Vec::new();
    for (cur_msg, pk) in msgs.iter() {

        let deserialised_msg: message::Message = serde_json::from_str(cur_msg.as_str())?;
        let verified = verify_msg((deserialised_msg,pk), valid_pks.clone())?;

        let final_verify = match verified {
            (true, Some(ret_pk))=> {
                valid_pks.push(ret_pk);
                true
            },
            (true, None)        => true,
            (false, _)          => false
        };

        println!("Verified status of msg: {}", final_verify);
        if !final_verify {
            return Ok(false);
        }
    }

    return Ok(true);
}

#[derive(Clone,PartialEq)]
pub enum PublickeyOwner {
    TransactingNode(String),
    Witness(String)
}

// Accepts a tuple of a message content and the sender's channel public key.
// If it is a valid TransactionMessage, it will return true and a valid channel public keys and it's ownership
pub fn verify_msg( (tx_msg,channel_pk) : (message::Message, &String), valid_pks: Vec<PublickeyOwner>) -> Result<(bool, Option<PublickeyOwner>)> {

    match tx_msg {
        message::Message::TransactionMsg {
            contract, witnesses, wit_node_sigs, tx_client_sigs
        } => {
            let tx_msg = TransactionMsg {contract, witnesses, wit_node_sigs, tx_client_sigs};
            let (ArrayOfWnSignitures(wit_sigs), ArrayOfTxSignitures(tn_sigs)) = get_sigs(tx_msg);
    
            for ws in wit_sigs.iter() {
                let (verified, pk) = verify_witness_sig(ws.clone())?;
                if !verified {
                    panic!("Signature verification failed")
                } else {
                    return Ok((true,Some(PublickeyOwner::TransactingNode(pk))));
                }
            }
            for ts in tn_sigs.iter() {
                let (verified, pk) = verify_tx_sig(ts.clone())?;
                if !verified {
                    panic!("Signature verification failed")
                } else {
                    return Ok((true,Some(PublickeyOwner::Witness(pk))));
                }
            }
        },
        message::Message::WitnessStatement {
            outcome,
        } => {
            let wrapped_channel_pk = PublickeyOwner::Witness(channel_pk.clone());
            if valid_pks.contains(&wrapped_channel_pk) {
                return Ok((true, None));
            }
        },
        _ => return Ok((false, None))
    }

    return Ok((false, None));
}

/* pub fn deserialise_msg(msg: String) -> Result<message::Message> {

    let deserialised_msg : message::Message = serde_json::from_str(msg.as_str())?;
    match deserialised_msg {
        message::Message::TransactionMsg {
            contract,
            witnesses,
            wit_node_sigs,
            tx_client_sigs,
        } => TransactionMsg {
                contract,
                witnesses,
                wit_node_sigs,
                tx_client_sigs,
            },
        message::Message::WitnessStatement {
            outcome,
        } => 
    }
/*     let deserialised_msg : serde_json::Result<message::Message> = serde_json::from_str(msg.as_str());
    if let Ok(des_msg) = deserialised_msg {
        return Ok(des_msg);
    } else {

        let deserialised_msg : message::Message = serde_json::from_str(msg.as_str())?;
        return Ok(deserialised_msg);

    } */
} */

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

// returns a bool indicating if valid, and a string of the channel pubkey of this sub
pub fn verify_witness_sig(sig: signatures::WitnessSig) -> Result<(bool, String)>{
    match sig {
        signatures::WitnessSig {
            contract,
            signer_channel_pubkey,
            timeout,
            signer_did_pubkey,
            signature,
        } => {
            let pre_sig = signatures::WitnessPreSig {
                contract,
                signer_channel_pubkey,
                timeout,
            };
            //println!("IMPORTANT: {:?}", pre_sig);

            let pre_sig = serde_json::to_string(&pre_sig).unwrap();

            let signer_did_pubkey = MethodData::PublicKeyMultibase(signer_did_pubkey);
            let decoded_pubkey = MethodData::try_decode(&signer_did_pubkey)?;
            let sig_unsigned = Ed25519::verify(pre_sig.as_bytes(), &signature, &decoded_pubkey);
            if let Ok(()) = sig_unsigned {
                return Ok((true,signer_channel_pubkey));
            } else {
                panic!("Signature verification failed")
            }
        }
    }
}

// returns a bool indicating if valid, and a string of the channel pubkey of this sub
pub fn verify_tx_sig(sig: signatures::TransactingSig) -> Result<(bool, String)>{
    match sig {
        signatures::TransactingSig {
            contract,
            signer_channel_pubkey,
            witnesses,
            wit_node_sigs,
            timeout,
            signer_did_pubkey,
            signature,
        } => {
            let pre_sig = signatures::TransactingPreSig {
                contract,
                signer_channel_pubkey,
                witnesses,
                wit_node_sigs,
                timeout,
            };

            let pre_sig = serde_json::to_string(&pre_sig).unwrap();

            let signer_did_pubkey = MethodData::PublicKeyMultibase(signer_did_pubkey);
            let decoded_pubkey = MethodData::try_decode(&signer_did_pubkey)?;
            let sig_unsigned = Ed25519::verify(pre_sig.as_bytes(), &signature, &decoded_pubkey);
            if let Ok(()) = sig_unsigned {
                return Ok((true,signer_channel_pubkey));
            } else {
                panic!("Signature verification failed")
            }
        }
    }
}