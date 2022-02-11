use crate::witness_rep::{
    iota_did::create_and_upload_did::{
        create_n_dids, Key
    },
    messages::{
        message, setup_msgs,
        signatures, transaction_msgs
    },
    transaction::generate_sigs
};
use crate::examples::{verify_messages, ALPH9};

use iota_streams::{
    app::transport::tangle::client::Client,
    app_channels::api::tangle::{
        Address, Author, Bytes, ChannelType, MessageContent, Subscriber,
        UnwrappedMessage, PublicKey
    },
    core::{println, Result},
    app::message::HasLink
};
use identity::{
    did::MethodData,
    crypto::{KeyPair, Ed25519, Sign}
};
use rand::Rng;

// because Client does not implement Copy trait, we need to pass
// the client as an exported byte array and reconstruct it
#[derive(Clone)]
pub struct ParticipantIdentity {
    pub channel_client: Vec<u8>,
    pub did_keypair: KeyPair
}

pub struct OrganizationIdentity {
    pub channel_client: Vec<u8>,
    pub did_keypair: KeyPair
}

pub async fn transact(
    contract: transaction_msgs::Contract,
    transacting_clients: &mut Vec<&mut Subscriber<Client>>,
    witness_clients: &mut Vec<&mut Subscriber<Client>>,
    transacting_did_kp: Vec<&KeyPair>,
    witness_did_kp: Vec<&KeyPair>,
    organization_client: &mut Author<Client>,
    organization_did_kp: &KeyPair
) -> Result<()> {
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
    }
    for i in 0..witness_clients.len() {
        witness_clients[i].receive_announcement(&ann_address).await?;
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
        let multibase_pub = MethodData::new_multibase(witness_clients[i].get_public_key());
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
    let mut prev_msg_link = announcement_link;
    transacting_clients[0].sync_state().await;
    transacting_clients[1].sync_state().await;
    witness_clients[0].sync_state().await;
    witness_clients[1].sync_state().await;
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
        println!("here");
        transacting_clients[0].sync_state().await;
        println!("here");
        transacting_clients[1].sync_state().await;
        println!("here");
        witness_clients[0].sync_state().await;
        println!("here");
        witness_clients[1].sync_state().await;
        println!("here");
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
    
    return Ok(());
}



pub async fn transact_skel(
    //contract: transaction_msgs::Contract,
    transacting_clients: &mut Vec<&mut Subscriber<Client>>,
    witness_clients: &mut Vec<&mut Subscriber<Client>>,
    //transacting_did_kp: Vec<&KeyPair>,
    //witness_did_kp: Vec<&KeyPair>,
    on_a: &mut Author<Client>,
    //organization_did_kp: &KeyPair
) -> Result<()> {
    
    const DEFAULT_TIMEOUT : u32 = 60*2; // 2 mins
    //--------------------------------------------------------------
    //--------------------------------------------------------------
    // ORGANIZATION SENDS ANOUNCEMENT AND SUBS PROCESS IT AND SUBSCRIBE
    // (IMITATING A KEYLOAD IN A MULTI-BRANCH/MULTI-PUB CHANNEL)
    //--------------------------------------------------------------
    let announcement_link = on_a.send_announce().await?;
    let ann_link_string = announcement_link.to_string();
    println!(
        "Announcement Link: {}\nTangle Index: {:#}\n",
        ann_link_string, announcement_link.to_msg_index()
    );

    
/*     // tn_a processes the channel announcement
    let ann_address = Address::try_from_bytes(&announcement_link.to_bytes())?;
    transacting_clients[0].receive_announcement(&ann_address).await?;

    // tn_a sends subscription message; these are the subscription links that
    // should be provided to the Author to complete subscription
    let subscribe_msg_tn_a = transacting_clients[0].send_subscribe(&ann_address).await?;
    let sub_msg_tn_a_str = subscribe_msg_tn_a.to_string();
    println!(
        "Subscription msgs:\n\tSubscriber TN_A: {}\n\tTangle Index: {:#}\n",
        sub_msg_tn_a_str, subscribe_msg_tn_a.to_msg_index()
    );


    // author processes the subscription message
    let sub_a_address = Address::try_from_bytes(&subscribe_msg_tn_a.to_bytes())?;
    on_a.receive_subscribe(&sub_a_address).await?; */




    // participants process the channel announcement
    let ann_address = Address::try_from_bytes(&announcement_link.to_bytes())?;
    for i in 0..transacting_clients.len() {
        transacting_clients[i].receive_announcement(&ann_address).await?;
        let subscribe_msg = transacting_clients[i].send_subscribe(&ann_address).await?;
        on_a.receive_subscribe(&subscribe_msg).await?;
    }
    for i in 0..witness_clients.len() {
        witness_clients[i].receive_announcement(&ann_address).await?;
        let subscribe_msg = witness_clients[i].send_subscribe(&ann_address).await?;
        on_a.receive_subscribe(&subscribe_msg).await?;
    }

 /*    let (keyload_a_link, _seq_a_link) =
    on_a.send_keyload_for_everyone(&announcement_link).await?;
    println!(
        "\nSent Keyload for TN_A and witnesses: {}",
        keyload_a_link
    ); */







    
    //////----------------------------------------------------------------------------- 
    ////    **non-current stages are skipped/assumed** 
    ////    STAGE 1 - TN_A CHECKS TO SEE IF THERE ARE AVAILABLE WITNESSES (WITHOUT COMMITING TO ANYTHING)
    ////    STAGE 2 (CURRENT) - TN_A REQUESTS TO TRANSACT WITH TN_B, TN_B ACCEPTS
    //////-----------------------------------------------------------------------------




    //////-----------------------------------------------------------------------------
    ////    STAGE 3 - TN_A AND TN_B FIND WITNESSES TO COMMIT TO THIS TRANSACTION
    ////    STAGE 4 - TN_A AND TN_B EXCHANGE WITNESSES 
    ////              (INCLUDES AGREEING UPON AND EJECTING EXCESS WITNESSES)
    ////    STAGE 5 (CURRENT) - WITNESSES SEND IN THEIR SIGNATURES
    ////////////-----------------------------------------------------------------------------



    
    //////-----------------------------------------------------------------------------
    ////    STAGE 6 (CURRENT) - TN_B SIGNS THE WITNESSES+CONTRACT, SENDS THIS TO TN_A. TN_A ALSO SIGNS HIS VERSION. 
    //////-----------------------------------------------------------------------------

    // TN_A signs the transaction


    //////-----------------------------------------------------------------------------
    ////    STAGE 7 (CURRENT) - TN_A SENDS THE TRANSACTION TO ON_A FOR APPROVAL, ON_A APPROVES
    //////-----------------------------------------------------------------------------
    


    //////-----------------------------------------------------------------------------
    ////    STAGE 8 (CURRENT) - WITNESSES AND TN_B SUBSCRIBE TO CHANNEL, AUTHOR ACCEPTS
    //////-----------------------------------------------------------------------------
    
    // witnesses process the channel announcement
    //// ideally we would have another address object (for realism), however this causes an error
    ////let ann_address = Address::try_from_bytes(&announcement_link.to_bytes())?;
/*     witness_clients[0].receive_announcement(&ann_address).await?;
    witness_clients[1].receive_announcement(&ann_address).await?;
    transacting_clients[1].receive_announcement(&ann_address).await?;

    // witnesses send subscription messages
    let subscribe_msg_wn_a = witness_clients[0].send_subscribe(&ann_address).await?;
    let subscribe_msg_wn_b = witness_clients[1].send_subscribe(&ann_address).await?;
    let subscribe_msg_tn_b = transacting_clients[1].send_subscribe(&ann_address).await?;
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
 */

    //////-----------------------------------------------------------------------------
    ////    STAGE 9  - GET THE PUBKEYS OF THE WITNESSES FROM THEM THROUGH TN_A
    ////              (BECAUSE THE PUBKEYS OF AUTHOR/SUB OBJECTS ARE DIFFERENT TO NODE PUBKEYS)
    ////    STAGE 10 (CURRENT) - ON_A SENDS A KEYLOAD FOR THIS TRANSACTION (INCLUDING TN_A AND WITNESSES)
    //////-----------------------------------------------------------------------------  


    // fetch subscriber public keys (for use by author in issuing a keyload);
    // we'll also use this to sort messages on the retrieval end
    let tn_a_pk = transacting_clients[0].get_public_key().as_bytes();
    let wn_a_pk = witness_clients[0].get_public_key().as_bytes();
    let wn_b_pk = witness_clients[0].get_public_key().as_bytes();
    let tn_b_pk = transacting_clients[1].get_public_key().as_bytes();
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
    on_a.send_keyload_for_everyone(&announcement_link).await?;
    println!(
        "\nSent Keyload for TN_A and witnesses: {}",
        keyload_a_link
    );

    //////-----------------------------------------------------------------------------
    ////    STAGE 11 (CURRENT) - TN_A SENDS THE TRANSACTION ON ON_A'S CHANNEL
    //////-----------------------------------------------------------------------------
    
    let msg_inputs_a = vec![
        "These".to_string(),
        "Messages".to_string(),
    ];

    // TN_A sends the transaction
    let mut prev_msg_link = keyload_a_link;
    sync_all(transacting_clients).await?;
    sync_all(witness_clients).await?;
    let (msg_link, _) = transacting_clients[0].send_signed_packet(
        &prev_msg_link,
        &Bytes(msg_inputs_a[0].as_bytes().to_vec()),
        &Bytes::default(),
    ).await?;
    println!("Sent msg from TN_A: {}, tangle index: {:#}", msg_link, msg_link.to_msg_index());
    prev_msg_link = msg_link;


    //////-----------------------------------------------------------------------------
    ////    STAGE 12 - WITNESSES SEE THE TRANSACTION IS UPLOADED
    ////    STAGE 13 - WITNESSES DECIDE THE PERCEIVED OUTCOME OF THE TRANSACTION AND UPDLOAD ACCORDINGLY
    ////               (DECISION BASED ON CUSTOMIZABLE FACTORS I.E. SENSORS, REPUTATION, ...)
    ////    STAGE 14 (CURRENT) - WITNESSES UPLOAD THEIR WITNESS STATEMENTS
    //////-----------------------------------------------------------------------------

    let witness_c_message = vec![
        "true".to_string(),
    ];

    let witness_d_message = vec![
        "true".to_string(),
    ];

    // WN_A sends their witness statement
    sync_all(transacting_clients).await?;
    sync_all(witness_clients).await?;
    let (msg_link, _) = witness_clients[0].send_signed_packet(
        &prev_msg_link,
        &Bytes(witness_c_message[0].as_bytes().to_vec()),
        &Bytes::default(),
    ).await?;
    println!("Sent msg from WN_A: {}, tangle index: {:#}", msg_link, msg_link.to_msg_index());
    prev_msg_link = msg_link;

    
    return Ok(());
}
/* 
pub async fn transact<'a>(
    transacting_nodes: Vec<ParticipantIdentity>,
    contract: transaction_msgs::Contract,
    witness_nodes: Vec<ParticipantIdentity>,
    organization_node: OrganizationIdentity,
    client: Client
) -> Result<()> {
    const DEFAULT_TIMEOUT : u32 = 60*2; // 2 mins
    //--------------------------------------------------------------
    //--------------------------------------------------------------
    // GENERATE CLIENTS FROM OUR SERIALISED CLIENTS
    //--------------------------------------------------------------

/*     let mut transacting_clients: Vec<&mut Subscriber<Client>> = Vec::new();
    for i in 0..transacting_nodes.len() {
        match &transacting_nodes[i] {
            ParticipantIdentity {
                channel_client,
                did_keypair
            } => {
                let mut sub = Subscriber::import(&channel_client, "pass", client.clone()).await?;
                transacting_clients.push(&mut sub);
            }
        }
    } */


/*     let transacting_clients: Vec<Subscriber<Client>> = extract_clients(transacting_nodes.clone(), client.clone()).await?;
    let witness_clients: Vec<Subscriber<Client>> = extract_clients(witness_nodes.clone(), client.clone()).await?;
 */
    

    //--------------------------------------------------------------
    // ORGANIZATION SENDS ANOUNCEMENT AND SUBS PROCESS IT
    // (IMITATING A KEYLOAD IN A MULTI-BRANCH/MULTI-PUB CHANNEL)
    //--------------------------------------------------------------
    let announcement_link;
    match organization_node {
        OrganizationIdentity {
            channel_client,
            did_keypair: _
        } => {
            announcement_link = Author::import(&channel_client, "pass", client.clone()).await?.send_announce().await?;
            let ann_link_string = announcement_link.to_string();
            println!(
                "Announcement Link: {}\nTangle Index: {:#}\n",
                ann_link_string, announcement_link.to_msg_index()
            );
        }
    }

    // participants process the channel announcement
    let ann_address = Address::try_from_bytes(&announcement_link.to_bytes())?;
    for mut participant in transacting_clients {
        participant.receive_announcement(&ann_address).await?;
    }
    for mut participant in witness_clients {
        participant.receive_announcement(&ann_address).await?;
    }

    //--------------------------------------------------------------
    // WITNESSES CREATE THEIR SIGNATURES FOR THE EVENT
    //--------------------------------------------------------------
    // Because of the borrowing rules of rust, we need to reconstruct the clients each time if we hold them in a Vec.
    // Problem stems from the fact that Subscriber<Client> is not clonable. OR NOT.....
    //let transacting_clients: Vec<Subscriber<Client>> = extract_clients(transacting_nodes.clone(), client.clone()).await?;
    for i in 0..witness_nodes.len() {
        let multibase_pub = MethodData::new_multibase(witness_clients[i].get_public_key());
        let channel_pk_as_multibase: String;
        if let MethodData::PublicKeyMultibase(mbpub) = multibase_pub {
            channel_pk_as_multibase = mbpub;
        }
        else {
            panic!("Could not encode public key as multibase")
        }

        let did_kp: KeyPair;
        if let ParticipantIdentity{channel_client, did_keypair} = witness_nodes[i].clone() {
            did_kp = did_keypair.clone();
        }

        let sig = generate_sigs::generate_witness_sig(contract, channel_pk_as_multibase, did_kp, DEFAULT_TIMEOUT: u32);
    }
    
    return Ok(());
} */


/* 
pub struct Identity<C> {
    channel_client: C,
    did_keypair: KeyPair
}

pub struct Participant(Identity<Subscriber<Client>>);
pub struct Org(Identity<Author<Client>>);

pub struct Participant(Identity<String>);
pub struct Org(Identity<String>);


pub fn get_clients<'a>(parts: Vec<&'a Participant>) -> Vec<&'a mut Subscriber<Client>> {
    // extract the transacting node's clients from the ids
    let mut clients: Vec<&'a mut Subscriber<Client>> = Vec::new();
    parts
        .iter()
        .map(|Participant(Identity{mut channel_client, did_keypair:_})|  {
            clients.push(&mut channel_client);
        });
    return clients;
} */

pub async fn extract_clients(participants: Vec<ParticipantIdentity>, client: Client) -> Result<Vec<Subscriber<Client>>> {
    let mut clients: Vec<Subscriber<Client>> = Vec::new();
    for i in 0..participants.len() {
        match &participants[i] {
            ParticipantIdentity {
                channel_client,
                did_keypair
            } => {
                let sub = Subscriber::import(&channel_client, "pass", client.clone()).await?;
                clients.push(sub);
            }
        }
    }
    return Ok(clients);
}

pub async fn sync_all(subs: &mut Vec<&mut Subscriber<Client>>) -> Result<()> {
    for sub in subs {
        sub.sync_state().await;
    }
    return Ok(());
}