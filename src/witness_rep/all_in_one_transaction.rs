use iota_streams::{
    app::transport::tangle::client::Client,
    app_channels::api::tangle::{
        Address, Author, Bytes, ChannelType, MessageContent, Subscriber,
        UnwrappedMessage, PublicKey
    },
    core::{println, Result},
};

use identity::crypto::PublicKey as IdPub;
use identity::crypto::PrivateKey;
use identity::{
    iota::IotaDocument,
    did::MethodData,
    crypto::{KeyPair, Ed25519, Sign}
};


use std::path::PathBuf;
//use identity::crypto::PublicKey;
use identity::account::AccountStorage;
use crate::examples::{verify_messages, ALPH9};
use crate::witness_rep::messages::{ 
    setup_msgs, transaction_msgs, signatures, witness_msgs
};
use crate::witness_rep::iota_did::create_and_upload_did::create_n_dids;
use crate::witness_rep::iota_did::create_and_upload_did::Key;
use crate::witness_rep::iota_did::get_pubkey_from_document::get_pubkey_from_document;
use rand::Rng;
use iota_streams::app::message::HasLink;

/**
 * Six nodes interaction:
 *  - Transacting node A (TN_A)
 *  - Transacting node B (TN_B)
 *  - Witness node A (WN_A)
 *  - Witness node B (WN_B)
 *  - Organization node A (ON_A)
 *  - Organization node B (ON_B)
 *
 *  TN_A and TN_B both gather their witness nodes e.g. TN_A finds WN_A, and TN_B finds WNB_,
 *  then by exchangeing the witness node ids, TN_B can create a signiture for the transaction
 *  which it then sends to TN_A, whom then attaches the packet to a tangle message.
 *  TN_A then needs to send the other nodes the announcement message.
 *  Depending on the terms being agreed upon, participants are compensated accordinly.
 *  e.g. In the car 'entering lane example', TN_A agrees to pay TN_B after the event,
 *       and both TN's agree to pay up to 5 witness nodes 0.1 IOTA. Thus, if TN_A and TN_B
 *       both find more than 5 combined, they must agree on which one to eject. After the
 *       event, the payment occurs. If payment does not occur, this will be obvious when
 *       scanning the event.
*/
pub async fn transact(node_url: &str) -> Result<()> {

    // CONSTANTS
    let DEFAULT_TIMEOUT : u32 = 60*2; // 2 mins

    //////
    ////    PREREQUISITES 1 (CURRENT) - HAVE A NETWORK OF CLIENTS CONNECTED TO NODES
    //////

    // cloned for each node; only for testing purposes where all participants are using the same node
    let client = Client::new_from_url(node_url);

    // create participants on the simulated network (num values used dynamically below)
    let num_tn = 2; 
    let num_wn = 2;
    let mut tn_a = Subscriber::new("Transacting Node A", client.clone());
    let mut tn_b = Subscriber::new("Transacting Node B", client.clone());
    let mut wn_a = Subscriber::new("Witness Node A", client.clone());
    let mut wn_b = Subscriber::new("Witness Node B", client.clone());

    //////
    ////    PREREQUISITES 2 (CURRENT) - ON_A ALREADY HAS A CHANNEL SET UP TO BE USED BY CLIENTS FOR THIS PURPOSE
    ////                                (CLIENTS MEANING THE ORGANIZATION'S CLIENTS, AS OPOSSED TO TANGLE CLIENT)
    ////    PREREQUISITES 3 (CURRENT) - TN_A, ON_A'S CLIENT, IS ALREADY A SUBSCRIBER OF ON_A'S CHANNEL
    //////
    
    // on_a generates a unique seed for the author
    let seed: &str = &(0..81)
        .map(|_| {
            ALPH9
                .chars()
                .nth(rand::thread_rng().gen_range(0, 27))
                .unwrap()
        })
        .collect::<String>();
    
    // on_a creates the channel
    let mut on_a = Author::new(seed, ChannelType::MultiBranch, client.clone());
    let announcement_link = on_a.send_announce().await?;
    let ann_link_string = announcement_link.to_string();
    println!(
        "Announcement Link: {}\nTangle Index: {:#}\n",
        ann_link_string, announcement_link.to_msg_index()
    );

    // tn_a processes the channel announcement
    let ann_address = Address::try_from_bytes(&announcement_link.to_bytes())?;
    tn_a.receive_announcement(&ann_address).await?;

    // tn_a sends subscription message; these are the subscription links that
    // should be provided to the Author to complete subscription
    let subscribe_msg_tn_a = tn_a.send_subscribe(&ann_address).await?;
    let sub_msg_tn_a_str = subscribe_msg_tn_a.to_string();
    println!(
        "Subscription msgs:\n\tSubscriber TN_A: {}\n\tTangle Index: {:#}\n",
        sub_msg_tn_a_str, subscribe_msg_tn_a.to_msg_index()
    );

    // author processes the subscription message
    let sub_a_address = Address::try_from_bytes(&subscribe_msg_tn_a.to_bytes())?;
    on_a.receive_subscribe(&sub_a_address).await?;
    
    ////// 
    ////    **non-current stages are skipped/assumed** 
    ////    STAGE 1 - TN_A CHECKS TO SEE IF THERE ARE AVAILABLE WITNESSES (WITHOUT COMMITING TO ANYTHING)
    ////    STAGE 2 (CURRENT) - TN_A REQUESTS TO TRANSACT WITH TN_B, TN_B ACCEPTS
    //////

    // gives us an array of (keypair,doc) variables for the particiants.
    // these are keypairs that sign the messages, not the author/sub keypair
    // [0]=TN_A    [1]=TN_B    [2]=WN_A    [3]=WN_B
    let did_details = create_n_dids(4).await?;
    
    let mut did_pubkeys : Vec<String> = did_details
                                            .iter()
                                            .map(|(_, (kp,_), _)| {
                                                let multibase_pub = MethodData::new_multibase(kp.public());

                                                if let MethodData::PublicKeyMultibase(mbpub) = multibase_pub {
                                                    return mbpub;
                                                }
                                                else {
                                                    return String::default();
                                                }
                                            })
                                            .collect();

    let mut did_privkeys : Vec<&Key> = did_details
                                            .iter()
                                            .map(|(_, (_,(privk,_)), _)| privk)
                                            .collect();
    
    let mut did_docs : Vec<&IotaDocument> = did_details
                                            .iter()
                                            .map(|(doc, _, _)| doc)
                                            .collect();

    let mut did_kps : Vec<&KeyPair> = did_details
                                            .iter()
                                            .map(|(_, (kp,_), _)| kp)
                                            .collect();
    
    // this gives us our private key, allowing us to sign data manually
    println!("{}", String::from_utf8_lossy(did_privkeys[0]));

    let contract_by_tn_a = transaction_msgs::Contract {
        contract_definition: String::from("tn_b allows tn_a to enter in front of it in the lane tn_b is in"),               
        participants: transaction_msgs::TransactingClients(
            Vec::from([did_pubkeys[0].clone(), did_pubkeys[1].clone()])
        ),      
        time: 1643572739,
        location: ((53, 20, 27.036),(6, 15, 2.695)),
    };

    // TN_A sends this, and TN_B replies with yes/no answer, or a timeout
    let setup_msg_by_tn_a = setup_msgs::SetupMessage {
        contract: contract_by_tn_a.clone(),
        max_witnesses: 5,
        payment_to_node: 0.1,
        max_payment_per_witness: 0.01,
    };


    //////
    ////    STAGE 3 - TN_A AND TN_B FIND WITNESSES TO COMMIT TO THIS TRANSACTION
    ////    STAGE 4 - TN_A AND TN_B EXCHANGE WITNESSES 
    ////              (INCLUDES AGREEING UPON AND EJECTING EXCESS WITNESSES)
    ////    STAGE 5 (CURRENT) - WITNESSES SEND IN THEIR SIGNATURES
    /////
    
    // WN_A signs their response
    let wn_a_pre_sig = signatures::WitnessPreSig {
        contract: contract_by_tn_a.clone(),
        timeout: DEFAULT_TIMEOUT,
    };
    let wn_a_pre_sig_bytes = serde_json::to_string(&wn_a_pre_sig)?;
    let wn_a_sig_bytes: [u8; 64]  = Ed25519::sign(&String::into_bytes(wn_a_pre_sig_bytes), did_kps[2].private())?;

    let wn_a_sig = signatures::WitnessSig {
        contract: contract_by_tn_a.clone(),
        timeout: DEFAULT_TIMEOUT,
        signature: wn_a_sig_bytes.to_vec(),
    };
    let wn_a_wrapped_sig_bytes = serde_json::to_string(&wn_a_sig)?;
    let wn_a_wrapped_sig_bytes = wn_a_wrapped_sig_bytes.as_bytes();

    // WN_B signs their response
    let wn_b_pre_sig = signatures::WitnessPreSig {
        contract: contract_by_tn_a.clone(),
        timeout: DEFAULT_TIMEOUT,
    };
    let wn_b_pre_sig_bytes = serde_json::to_string(&wn_b_pre_sig)?;
    let wn_b_sig_bytes: [u8; 64]  = Ed25519::sign(&String::into_bytes(wn_b_pre_sig_bytes), did_kps[3].private())?;

    let wn_b_sig = signatures::WitnessSig {
        contract: contract_by_tn_a.clone(),
        timeout: DEFAULT_TIMEOUT,
        signature: wn_b_sig_bytes.to_vec(),
    };
    let wn_b_wrapped_sig_bytes = serde_json::to_string(&wn_b_sig)?;
    let wn_b_wrapped_sig_bytes = wn_b_wrapped_sig_bytes.as_bytes();

    
    //////
    ////    STAGE 6 (CURRENT) - TN_B SIGNS THE WITNESSES+CONTRACT, SENDS THIS TO TN_A. TN_A ALSO SIGNS HIS VERSION. 
    //////

    // TN_A signs the transaction
    let tn_a_tx_msg_pre_sig = transaction_msgs::TransactionMsgPreSig {
        contract: contract_by_tn_a.clone(),
        witnesses: transaction_msgs::WitnessClients(Vec::from([did_pubkeys[2].clone(), did_pubkeys[3].clone()])),
        wit_node_sigs: transaction_msgs::ArrayOfSignitures(
            [
                transaction_msgs::Signature(wn_a_wrapped_sig_bytes.to_vec()),
                transaction_msgs::Signature(wn_b_wrapped_sig_bytes.to_vec())
            ]
            .to_vec()
        ),
    };
    let tn_a_tx_msg_pre_sig_bytes = serde_json::to_string(&tn_a_tx_msg_pre_sig)?;
    let tn_a_tx_msg_sig: [u8; 64]  = Ed25519::sign(&String::into_bytes(tn_a_tx_msg_pre_sig_bytes), did_kps[0].private())?;

    // TN_B signs the transaction
    let tn_b_tx_msg_pre_sig = transaction_msgs::TransactionMsgPreSig {
        contract: contract_by_tn_a.clone(),
        witnesses: transaction_msgs::WitnessClients(Vec::from([did_pubkeys[2].clone(), did_pubkeys[3].clone()])),
        wit_node_sigs: transaction_msgs::ArrayOfSignitures(
            [
                transaction_msgs::Signature(wn_a_sig_bytes.to_vec()),
                transaction_msgs::Signature(wn_b_sig_bytes.to_vec())
            ]
            .to_vec()
        ),
    };
    let tn_b_tx_msg_pre_sig_bytes = serde_json::to_string(&tn_b_tx_msg_pre_sig)?;
    let tn_b_tx_msg_sig: [u8; 64]  = Ed25519::sign(&String::into_bytes(tn_b_tx_msg_pre_sig_bytes), did_kps[1].private())?;
    
    // TN_A, having received these signatures, builds the final transaction
    let transaction_msg = transaction_msgs::TransactionMsg {
        contract: contract_by_tn_a.clone(),
        witnesses: transaction_msgs::WitnessClients(Vec::from([did_pubkeys[2].clone(), did_pubkeys[3].clone()])),
        wit_node_sigs: transaction_msgs::ArrayOfSignitures(
            [
                transaction_msgs::Signature(wn_a_sig_bytes.to_vec()),
                transaction_msgs::Signature(wn_b_sig_bytes.to_vec())
            ]
            .to_vec()
        ),
        tx_client_sigs: transaction_msgs::ArrayOfSignitures(
            [
                transaction_msgs::Signature(tn_a_tx_msg_sig.to_vec()),
                transaction_msgs::Signature(tn_b_tx_msg_sig.to_vec())
            ]
            .to_vec()
        ),
    };

    //////
    ////    STAGE 7 (CURRENT) - TN_A SENDS THE TRANSACTION TO ON_A FOR APPROVAL, ON_A APPROVES
    //////
    
    // a bool that gets checked below when the author is about to form the branch
    let on_a_auth : Result<bool, ()> = Err(());
    //let on_a_auth : Result<bool, ()> = Ok(true);

    //////
    ////    STAGE 8 (CURRENT) - WITNESSES AND TN_B SUBSCRIBE TO CHANNEL, AUTHOR ACCEPTS
    //////
    
    // witnesses process the channel announcement
    let ann_address = Address::try_from_bytes(&announcement_link.to_bytes())?;
    wn_a.receive_announcement(&ann_address).await?;
    wn_b.receive_announcement(&ann_address).await?;
    tn_b.receive_announcement(&ann_address).await?;

    // witnesses send subscription messages
    let subscribe_msg_wn_a = wn_a.send_subscribe(&ann_address).await?;
    let subscribe_msg_wn_b = wn_b.send_subscribe(&ann_address).await?;
    let subscribe_msg_tn_b = tn_b.send_subscribe(&ann_address).await?;
    let sub_msg_wn_a_str = subscribe_msg_wn_a.to_string();
    let sub_msg_wn_b_str = subscribe_msg_wn_b.to_string();
    let sub_msg_tn_b_str = subscribe_msg_tn_b.to_string();
    println!(
        "Subscription msgs:\n\tSubscriber WN_A: {}\n\tTangle Index: {:#}\n",
        sub_msg_wn_a_str, subscribe_msg_wn_a.to_msg_index()
    );
    println!(
        "Subscription msgs:\n\tSubscriber WN_B: {}\n\tTangle Index: {:#}\n",
        sub_msg_wn_b_str, subscribe_msg_wn_b.to_msg_index()
    );
    println!(
        "Subscription msgs:\n\tSubscriber TN_A: {}\n\tTangle Index: {:#}\n",
        sub_msg_tn_b_str, subscribe_msg_tn_b.to_msg_index()
    );

    // Note that: sub_a = tn_a, sub_b = wn_a, sub_c = wn_b, sub_d = tn_b
    let sub_b_address = Address::try_from_bytes(&subscribe_msg_wn_a.to_bytes())?;
    let sub_c_address = Address::try_from_bytes(&subscribe_msg_wn_b.to_bytes())?;
    let sub_d_address = Address::try_from_bytes(&subscribe_msg_tn_b.to_bytes())?;

    on_a.receive_subscribe(&sub_b_address).await?;
    on_a.receive_subscribe(&sub_c_address).await?;
    on_a.receive_subscribe(&sub_d_address).await?;


    //////
    ////    STAGE 9  - GET THE PUBKEYS OF THE WITNESSES FROM THEM THROUGH TN_A
    ////              (BECAUSE THE PUBKEYS OF AUTHOR/SUB OBJECTS ARE DIFFERENT TO NODE PUBKEYS)
    ////    STAGE 10 (CURRENT) - ON_A SENDS A KEYLOAD FOR THIS TRANSACTION (INCLUDING TN_A AND WITNESSES)
    //////  

    // ON_A only uploads the keyload if they have already authorised the transaction
    if let Err(()) = on_a_auth {
        panic!("ON_A did not authorise the branch");
    }
    
    // fetch subscriber public keys (for use by author in issuing a keyload);
    // we'll also use this to sort messages on the retrieval end
    let tn_a_pk = tn_a.get_public_key().as_bytes();
    let wn_a_pk = wn_a.get_public_key().as_bytes();
    let wn_b_pk = wn_b.get_public_key().as_bytes();
    let tn_b_pk = tn_b.get_public_key().as_bytes();
    let pks = vec![
        PublicKey::from_bytes(tn_a_pk)?,
        PublicKey::from_bytes(wn_a_pk)?,
        PublicKey::from_bytes(wn_b_pk)?,
        PublicKey::from_bytes(tn_b_pk)?,
    ];

    // Author sends keyload with the public keys of TN_A and witnesses to generate a new
    // branch. This will return a tuple containing the message links. The first is the
    // message link itself, the second is the sequencing message link.
    let (keyload_a_link, _seq_a_link) =
    on_a.send_keyload(&announcement_link, &vec![pks[0].into(), pks[1].into(), pks[2].into(),  pks[3].into()]).await?;
    println!(
        "\nSent Keyload for TN_A and witnesses: {}, tangle index: {:#}",
        keyload_a_link,
        _seq_a_link.unwrap()
    );

    //////
    ////    STAGE 11 (CURRENT) - TN_A SENDS THE TRANSACTION ON ON_A'S CHANNEL
    //////
    
    // serialise the tx
    let tx_msg_str = serde_json::to_string(&transaction_msg)?; 
    let tx_message = vec![
        tx_msg_str
    ];

    // TN_A sends the transaction
    let mut prev_msg_link = keyload_a_link;
    tn_a.sync_state().await;
    let (msg_link, _) = tn_a.send_signed_packet(
        &prev_msg_link,
        &Bytes::default(),
        &Bytes(tx_message[0].as_bytes().to_vec()),
    ).await?;
    println!("Sent msg from TN_A: {}, tangle index: {:#}", msg_link, msg_link.to_msg_index());
    prev_msg_link = msg_link;


    //////
    ////    STAGE 12 - WITNESSES SEE THE TRANSACTION IS UPLOADED
    ////    STAGE 13 - WITNESSES DECIDE THE PERCEIVED OUTCOME OF THE TRANSACTION AND UPDLOAD ACCORDINGLY
    ////               (DECISION BASED ON CUSTOMIZABLE FACTORS I.E. SENSORS, REPUTATION, ...)
    ////    STAGE 14 (CURRENT) - WITNESSES UPLOAD THEIR WITNESS STATEMENTS
    //////

    // WN_A's prepares their statement
    let wn_a_statement = witness_msgs::WitnessStatement {
        outcome: true
    };
    let wn_a_statement_string = serde_json::to_string(&wn_a_statement)?;

    let witness_a_message = vec![
        wn_a_statement_string
    ];

    // WN_B's prepares their statement
    let wn_b_statement = witness_msgs::WitnessStatement {
        outcome: true
    };
    let wn_b_statement_string = serde_json::to_string(&wn_b_statement)?;

    let witness_b_message = vec![
        wn_b_statement_string
    ];

    // WN_A sends their witness statement
    wn_a.sync_state().await;
    let (msg_link, _) = wn_a.send_signed_packet(
        &prev_msg_link,
        &Bytes::default(),
        &Bytes(witness_a_message[0].as_bytes().to_vec()),
    ).await?;
    println!("Sent msg from WN_A: {}, tangle index: {:#}", msg_link, msg_link.to_msg_index());
    prev_msg_link = msg_link;

    // WN_B sends their witness statement
    wn_b.sync_state().await;
    let (msg_link, _) = wn_b.send_signed_packet(
        &prev_msg_link,
        &Bytes::default(),
        &Bytes(witness_b_message[0].as_bytes().to_vec()),
    ).await?;
    println!("Sent msg from WN_B: {}, tangle index: {:#}", msg_link, msg_link.to_msg_index());
    prev_msg_link = msg_link;

    //////
    ////    STAGE 15 (CURRENT) - ALL PARTIES, BOTH INVOLVED AND NOT INVOLVED, CAN NOW SCAN THE TRANSACTION
    //////

    // -----------------------------------------------------------------------------
    // Author can now fetch these messages
    let mut retrieved = on_a.fetch_all_next_msgs().await;
    println!("\nAuthor found {} messages", retrieved.len());

    let mut retrieved_lists = split_retrieved(&mut retrieved, pks);
    println!("\nVerifying message retrieval: Author");
    verify_messages(&tx_message, retrieved_lists.remove(0))?;

    //////
    ////    STAGE 16 (CURRENT) - RELEVANT NODES COMPENSATE THE PREDEFINED NODES TO BE COMPENSATED
    //////

    let compensation_tx_tn_a = vec![
        "{
            \'pay_to_tn_b\': 0.1,
            \'pay_to_wn_a\': 0.01,
            \'pay_to_wn_b\': 0.01,
        }"
    ];

    // TN_A sends the compensation transaction
    tn_a.sync_state().await;
    let (msg_link, _) = tn_a.send_signed_packet(
        &prev_msg_link,
        &Bytes::default(),
        &Bytes(compensation_tx_tn_a[0].as_bytes().to_vec()),
    ).await?;
    println!("Sent msg from TN_A: {}, tangle index: {:#}", msg_link, msg_link.to_msg_index());
    prev_msg_link = msg_link;

    let compensation_tx_tn_b = vec![
        "{
            \'pay_to_wn_a\': 0.01,
            \'pay_to_wn_b\': 0.01,
        }"
    ];

    // TN_B sends the compensation transaction
    tn_a.sync_state().await;
    let (msg_link, _) = tn_a.send_signed_packet(
        &prev_msg_link,
        &Bytes::default(),
        &Bytes(compensation_tx_tn_b[0].as_bytes().to_vec()),
    ).await?;
    println!("Sent msg from TN_B: {}, tangle index: {:#}", msg_link, msg_link.to_msg_index());
    //prev_msg_link = msg_link;

    //////
    ////    ------FINISHED------
    //////

    Ok(())
}

// Sorts the messages on the channel according to the public keys of the publisher
fn split_retrieved(
    retrieved: &mut Vec<UnwrappedMessage>,
    pks: Vec<PublicKey>,
) -> Vec<Vec<UnwrappedMessage>> {
    let mut retrieved_msgs_a = Vec::new();
    let mut retrieved_msgs_b = Vec::new();
    let mut retrieved_msgs_c = Vec::new();

    // Sort messages by sender
    for _ in 0..retrieved.len() {
        let msg = retrieved.remove(0);
        let pk = match msg.body {
            MessageContent::SignedPacket {
                pk,
                public_payload: _,
                masked_payload: _,
            } => pk,
            _ => PublicKey::default(),
        };

        if pk == pks[0] {
            retrieved_msgs_a.push(msg);
        } else if pk == pks[1] {
            retrieved_msgs_b.push(msg);
        } else if pk == pks[2] {
            retrieved_msgs_c.push(msg);
        }
    }

    vec![
        retrieved_msgs_a,
        retrieved_msgs_b,
        retrieved_msgs_c,
    ]
}
