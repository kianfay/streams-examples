use crate::witness_rep::{
    messages::{
        message, signatures, transaction_msgs
    },
    transaction::generate_sigs
};

use iota_streams::{
    app::transport::tangle::client::Client,
    app_channels::api::tangle::{
        Address, Author, Bytes, Subscriber,
    },
    core::{println, Result},
    app::message::HasLink
};
use identity::{
    did::MethodData,
    crypto::KeyPair
};


pub async fn sync_all(subs: &mut Vec<&mut Subscriber<Client>>) -> Result<()> {
    for sub in subs {
        sub.sync_state().await;
    }
    return Ok(());
}

pub async fn transact(
    contract: transaction_msgs::Contract,
    transacting_clients: &mut Vec<&mut Subscriber<Client>>,
    witness_clients: &mut Vec<&mut Subscriber<Client>>,
    transacting_did_kp: Vec<&KeyPair>,
    witness_did_kp: Vec<&KeyPair>,
    organization_client: &mut Author<Client>,
    organization_did_kp: &KeyPair
) -> Result<String> {
    const DEFAULT_TIMEOUT : u32 = 60*2; // 2 mins

    //--------------------------------------------------------------
    //--------------------------------------------------------------
    // ORGANIZATION SENDS ANOUNCEMENT AND SUBS PROCESS IT
    // (IMITATING A KEYLOAD IN A MULTI-BRANCH/MULTI-PUB CHANNEL)
    //--------------------------------------------------------------
    let announcement_link = organization_client.send_announce().await?;
    let ann_link_string = announcement_link.to_string();
    println!(
        "Announcement Link: {}\nTangle Index: {:#}\n",
        ann_link_string, announcement_link.to_msg_index()
    );

    // participants process the channel announcement
    let ann_address = Address::try_from_bytes(&announcement_link.to_bytes())?;
    for i in 0..transacting_clients.len() {
        transacting_clients[i].receive_announcement(&ann_address).await?;
        let subscribe_msg = transacting_clients[i].send_subscribe(&ann_address).await?;
        organization_client.receive_subscribe(&subscribe_msg).await?;
    }
    for i in 0..witness_clients.len() {
        witness_clients[i].receive_announcement(&ann_address).await?;
        let subscribe_msg = witness_clients[i].send_subscribe(&ann_address).await?;
        organization_client.receive_subscribe(&subscribe_msg).await?;
    }

    let (keyload_a_link, _seq_a_link) =
    organization_client.send_keyload_for_everyone(&announcement_link).await?;
    println!(
        "\nSent Keyload for TN_A and witnesses: {}",
        keyload_a_link
    );

    //--------------------------------------------------------------
    // WITNESSES GENERATE SIGS
    //--------------------------------------------------------------

    let mut witness_sigs: Vec<signatures::WitnessSig> = Vec::new();
    for i in 0..witness_clients.len() {
        let multibase_pub = MethodData::new_multibase(witness_clients[i].get_public_key());
        let channel_pk_as_multibase: String;
        if let MethodData::PublicKeyMultibase(mbpub) = multibase_pub {
            channel_pk_as_multibase = mbpub;
        }
        else {
            panic!("Could not encode public key as multibase")
        }

        let sig = generate_sigs::generate_witness_sig(contract.clone(),
            channel_pk_as_multibase,
            witness_did_kp[i].clone(),
            DEFAULT_TIMEOUT
        )?;
        witness_sigs.push(sig);
    }

    //--------------------------------------------------------------
    // TRANSACTING NODES GENERATE SIGS
    //--------------------------------------------------------------

    let witnesses: Vec<transaction_msgs::PublicKey> = witness_did_kp
        .iter()
        .map(|kp| {
            let multibase_pub = MethodData::new_multibase(kp.public());
            if let MethodData::PublicKeyMultibase(mbpub) = multibase_pub {
                return mbpub
            }
            else {
                panic!("Could not encode public key as multibase")
            }
        })
        .collect();

    let mut transacting_sigs: Vec<signatures::TransactingSig> = Vec::new();
    for i in 0..transacting_clients.len() {
        let multibase_pub = MethodData::new_multibase(transacting_clients[i].get_public_key());
        let channel_pk_as_multibase: String;
        if let MethodData::PublicKeyMultibase(mbpub) = multibase_pub {
            channel_pk_as_multibase = mbpub;
        }
        else {
            panic!("Could not encode public key as multibase")
        }
        let sig = generate_sigs::generate_transacting_sig(
            contract.clone(),
            channel_pk_as_multibase,
            transacting_did_kp[i].clone(),
            transaction_msgs::WitnessClients(witnesses.clone()),
            transaction_msgs::ArrayOfWnSignitures(witness_sigs.clone()),
            DEFAULT_TIMEOUT
        )?;
        transacting_sigs.push(sig);
    }

    //--------------------------------------------------------------
    // INITIATING TN, HAVING REVEIVED THE SIGNATURES, 
    // BUILD FINAL TRANSACTION (TN = TRANSACTING NODE)
    //--------------------------------------------------------------

    let transaction_msg = message::Message::TransactionMsg {
        contract: contract.clone(),
        witnesses: transaction_msgs::WitnessClients(witnesses.clone()),
        wit_node_sigs: transaction_msgs::ArrayOfWnSignitures(witness_sigs.clone()),
        tx_client_sigs: transaction_msgs::ArrayOfTxSignitures(transacting_sigs.clone()),
    };
    
    //--------------------------------------------------------------
    // INITIATING TN SENDS THE TRANSACTION MESSAGE
    //--------------------------------------------------------------

    // serialise the tx
    let tx_msg_str = serde_json::to_string(&transaction_msg)?; 
    let tx_message = vec![
        tx_msg_str
    ];

    // TN_A sends the transaction
    let mut prev_msg_link = keyload_a_link;
    sync_all(transacting_clients).await?;
    sync_all(witness_clients).await?;
    let (msg_link, _) = transacting_clients[0].send_signed_packet(
        &prev_msg_link,
        &Bytes(tx_message[0].as_bytes().to_vec()),
        &Bytes::default(),
    ).await?;
    println!("Sent msg from TN_A: {}, tangle index: {:#}", msg_link, msg_link.to_msg_index());
    prev_msg_link = msg_link;

    //--------------------------------------------------------------
    // THE EVENT IN QUESTION ON THE CONTRACT PLAYS OUT
    // (WE GENERATE THE OUTCOME AS PART OF THE SIMULATION)
    //--------------------------------------------------------------

    // TODO

    //--------------------------------------------------------------
    // WITNESSES SEND THEIR STATMENTS
    //--------------------------------------------------------------

    for i in 0..witness_clients.len(){

        // WN's prepares their statement
        let wn_statement = message::Message::WitnessStatement {
            outcome: true
        };
        let wn_statement_string = serde_json::to_string(&wn_statement)?;

        let witness_message = vec![
            wn_statement_string
        ];

        // WN sends their witness statement
        sync_all(transacting_clients).await?;
        sync_all(witness_clients).await?;
        let (msg_link, _) = witness_clients[i].send_signed_packet(
            &prev_msg_link,
            &Bytes(witness_message[0].as_bytes().to_vec()),
            &Bytes::default(),
        ).await?;
        println!("Sent msg from WN_{}: {}, tangle index: {:#}", i, msg_link, msg_link.to_msg_index());
        prev_msg_link = msg_link;
    }

    //--------------------------------------------------------------
    // THE PARTICIPANTS READ THE STATEMENTS AND DECIDE TO COMPENSATE
    // OR NOT (NOT WOULD IN PRINCIPAL BE A DISHONEST CHOICE)
    //--------------------------------------------------------------

    // TODO - add read and choice

    for i in 0..transacting_clients.len(){

        // TODO - certain TNs need to compensate other TNs

        // TN prepares the compensation transaction 
        let payments_tn_a = vec![
            //"tn_b: 0.1".to_string(),
            "wn_a: 0.01".to_string(),
            "wn_b: 0.01".to_string()
        ];
        let compensation_msg = message::Message::CompensationMsg {
            payments: payments_tn_a
        };
        let compensation_msg_str = serde_json::to_string(&compensation_msg)?;

        let compensation_tx = vec![
            compensation_msg_str
        ];

        // TN sends the compensation transaction
        sync_all(transacting_clients).await?;
        sync_all(witness_clients).await?;
        let (msg_link, _) = transacting_clients[i].send_signed_packet(
            &prev_msg_link,
            &Bytes(compensation_tx[0].as_bytes().to_vec()),
            &Bytes::default(),
        ).await?;
        println!("Sent msg from TN_{}: {}, tangle index: {:#}", i, msg_link, msg_link.to_msg_index());
        prev_msg_link = msg_link;
    }
    
    return Ok(ann_link_string);
}
