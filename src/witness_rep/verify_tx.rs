// can use serde_json::from_str(...) to get it to be a trans
use crate::witness_rep::messages::signatures;
use crate::witness_rep::messages::transaction_msgs::{
    TransactionMsg, ArrayOfTxSignitures, ArrayOfWnSignitures 
};

use identity::crypto::{Ed25519, Verify};

pub fn verify_tx(tx: TransactionMsg, tn_pubkey: Vec<String>, wn_pubkey: Vec<String>) -> bool {

    let (ArrayOfWnSignitures(wit_sigs), ArrayOfTxSignitures(tn_sigs)) = get_sigs(tx);
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