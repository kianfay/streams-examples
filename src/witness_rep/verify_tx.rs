use identity::crypto::{Ed25519, Verify};
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

use crate::witness_rep::messages::signatures;
use crate::witness_rep::messages::transaction_msgs::{
    TransactionMsg, ArrayOfTxSignitures, ArrayOfWnSignitures 
};

pub async fn verify_tx(node_url: &str, ann_msg: String) -> Result<bool> {
    
    // create the subscriber
    let client = Client::new_from_url(node_url);
    let mut verifier_sub = Subscriber::new("SubscriberA", client);

    // Generate an Address object from the provided announcement link string from the Author
    let ann_address = Address::from_str(&ann_msg)?;

    // Receive the announcement message to start listening to the channel
    verifier_sub.receive_announcement(&ann_address).await?;

    // fetch and extract the messages
    let retrieved = verifier_sub.fetch_all_next_msgs().await;
    for i in 0..retrieved.len() {
        println!("{:?}", retrieved[i]);
    }
    let msgs = extract_msgs::extract_msg(retrieved);

    // deserialise the messages into their correct types
    println!("{:?}", msgs);

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