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



pub async fn transact_skel(node_url: &str) -> Result<()> {
    const DEFAULT_TIMEOUT : u32 = 60*2; // 2 mins

    let client = Client::new_from_url(node_url);

    let mut tn_a = Subscriber::new("Transacting Node A", client.clone());
    let mut tn_b = Subscriber::new("Transacting Node B", client.clone());
    let mut wn_a = Subscriber::new("Witness Node A", client.clone());
    let mut wn_b = Subscriber::new("Witness Node B", client.clone());

    let transacting_clients: &mut Vec<&mut Subscriber<Client>> = &mut vec![&mut tn_a,&mut  tn_b];
    let witness_clients:&mut Vec<&mut Subscriber<Client>> = &mut vec![&mut wn_a,&mut  wn_b];  
    
    // generate channel author
    let seed: &str = &(0..81)
        .map(|_| {
            ALPH9
                .chars()
                .nth(rand::thread_rng().gen_range(0, 27))
                .unwrap()
        })
        .collect::<String>();
    
    let mut organization_client = Author::new(seed, ChannelType::SingleBranch, client.clone());

    //--------------------------------------------------------------
    //--------------------------------------------------------------
    // ORGANIZATION SENDS ANOUNCEMENT AND SUBS PROCESS IT AND SUBSCRIBE
    // (IMITATING A KEYLOAD IN A MULTI-BRANCH/MULTI-PUB CHANNEL)
    //--------------------------------------------------------------
    let announcement_link = organization_client.send_announce().await?;
    let ann_link_string = announcement_link.to_string();
    println!(
        "Announcement Link: {}\nTangle Index: {:#}\n",
        ann_link_string, announcement_link.to_msg_index()
    );

    // participants process the channel announcement and subscribe
    let ann_address = Address::try_from_bytes(&announcement_link.to_bytes())?;
    for i in 0..transacting_clients.len() {
        transacting_clients[i].receive_announcement(&ann_address).await?;
            
        // tn sends subscription message; these are the subscription links that
        // should be provided to the Author to complete subscription
        let subscribe_msg = transacting_clients[i].send_subscribe(&ann_address).await?;
        let sub_msg_str = subscribe_msg.to_string();
        println!(
            "Subscription msgs:\n\tSubscriber TN_A: {}\n\tTangle Index: {:#}\n",
            sub_msg_str, subscribe_msg.to_msg_index()
        );

        let sub_address = Address::try_from_bytes(&subscribe_msg.to_bytes())?;
        organization_client.receive_subscribe(&sub_address).await?;
    }
    for i in 0..witness_clients.len() {
        witness_clients[i].receive_announcement(&ann_address).await?;

        // wn sends subscription message; these are the subscription links that
        // should be provided to the Author to complete subscription
        let subscribe_msg = witness_clients[i].send_subscribe(&ann_address).await?;
        let sub_msg_str = subscribe_msg.to_string();
        println!(
            "Subscription msgs:\n\tSubscriber TN_{}: {}\n\tTangle Index: {:#}\n",
            i, sub_msg_str, subscribe_msg.to_msg_index()
        );
        
        let sub_address = Address::try_from_bytes(&subscribe_msg.to_bytes())?;
        organization_client.receive_subscribe(&sub_address).await?;
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


    //--------------------------------------------------------------
    // TRANSACTING NODES GENERATE SIGS
    //--------------------------------------------------------------

    //--------------------------------------------------------------
    // INITIATING TN, HAVING REVEIVED THE SIGNATURES, 
    // BUILD FINAL TRANSACTION (TN = TRANSACTING NODE)
    //--------------------------------------------------------------

    
    //--------------------------------------------------------------
    // INITIATING TN SENDS THE TRANSACTION MESSAGE
    //--------------------------------------------------------------

    // serialise the tx
    let tx_msg_str = String::from("heyy"); 
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

        let wn_statement_string = String::from("heyy"); 

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

        let compensation_msg_str = String::from("heyy"); 

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