use crate::witness_rep::{
    iota_did::create_and_upload_did::Key,
    messages::{
        message, signatures, transaction_msgs
    },
    transaction::generate_sigs,
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
use rand::Rng;


// The identity captures the channel client and the associated keypair,
// as well as the keypair associated to the participants DID. It also has their 
// 'reliability', [0,1], an unambiguous/simplistic measure of the honesty of their
// actions. A score of 1 means they are always honest, and 0 means always dishonest.
// A more dishonest participant will more likely to give a either not uphold their
// half of an agreement, or more likely to give a lazy witness statement (i.e. not
// depending on the actual event), or to possibly collude or act with malice to 
// either gain an advantage in monetary or trust score terms (or damage other 
// participant).
pub struct Identity<C> {
    pub channel_client: C,
    pub did_key: Key,
    pub reliability: f32,
}

pub type ParticipantIdentity = Identity<Subscriber<Client>>;

#[derive(Clone)]
pub enum LazyMethod {
    Constant(bool),
    Random,
}

//pub type OrganizationIdentity = Identity<Author<Client>>;

pub fn extract_from_id(id: &mut ParticipantIdentity) -> Result<(&mut Subscriber<Client>, KeyPair, f32)> {
    match id {
        ParticipantIdentity { 
            channel_client,
            did_key,
            reliability
        } => {
            let did_keypair = KeyPair::try_from_ed25519_bytes(did_key)?;
            return Ok((channel_client, did_keypair,reliability.clone()));
        }
    }
}

pub fn extract_from_ids(ids: &mut Vec<ParticipantIdentity>) -> Result<(Vec<&mut Subscriber<Client>>, Vec<KeyPair>, Vec<f32>)> {
    let mut subs: Vec<&mut Subscriber<Client>>  = Vec::new();
    let mut kps : Vec<KeyPair>                  = Vec::new();
    let mut rels: Vec<f32>                      = Vec::new();

    for id in ids {
        let (sub, kp, rel) = extract_from_id(id)?;
        subs.push(sub);
        kps.push(kp);
        rels.push(rel);
    }
    return Ok((subs, kps,rels));
}

pub async fn sync_all(subs: &mut Vec<&mut Subscriber<Client>>) -> Result<()> {
    for sub in subs {
        sub.sync_state().await;
    }
    return Ok(());
}

// The offset parameter is to allow for a node not to be targeted to be made dishonest. 
// Situations such as the inititation node never acting dishonest require this.
pub fn get_honest_nodes(participants_reliablity: Vec<f32>, offset: usize) -> Vec<bool>{
    let mut honest_nodes: Vec<bool> = vec![true; participants_reliablity.len()];

    // for all but the initiating node, who for now we assume to be always acting as honest
    // because they are paying for everything to go smoothly
    for i in offset..participants_reliablity.len() {

        // randomly assert if they are acting honest based on their reliability
        let rand: f32 = rand::thread_rng().gen();
        println!("Trying transacting node {}. Rand={}", i, rand);
        let acting_honest: bool = participants_reliablity[i] > rand;
        if acting_honest {
            honest_nodes[i] = false;
        }
    }

    return honest_nodes;
}

pub fn lazy_outcome(lazy_method: &LazyMethod) -> bool {
    return match lazy_method {
        LazyMethod::Constant(output) => output.clone(),
        LazyMethod::Random => {
            let rand: f32 = rand::thread_rng().gen();
            println!("Trying lazy outcome. Rand={}", rand);
            if rand > 0.5 {
                true
            } else {
                false
            }
        }
    }
}


pub async fn transact(
    contract: transaction_msgs::Contract,
    transacting_ids: &mut Vec<ParticipantIdentity>,
    witness_ids: &mut Vec<ParticipantIdentity>,
    organization_client: &mut Author<Client>,
    lazy_method: LazyMethod
) -> Result<String> {
    const DEFAULT_TIMEOUT : u32 = 60*2; // 2 mins

    //--------------------------------------------------------------
    //--------------------------------------------------------------
    // EXTRACT CLIENTS AND KEYPAIRS FROM IDENTITIES
    //--------------------------------------------------------------
    let (mut transacting_clients, transacting_did_kp, transacting_reliablity) = extract_from_ids(transacting_ids)?;
    let (mut witness_clients, witness_did_kp, witness_reliability) = extract_from_ids(witness_ids)?;


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
    sync_all(&mut transacting_clients).await?;
    sync_all(&mut witness_clients).await?;
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

    // Dishonest transacting nodes still want to get compensated, but are rellying
    // on lazy (or colluding) witnesses for compensation to be more likely. Reason
    // being, the counterparty may still compensate them even if they act dishonestly,
    // but only if the witnesses side with the dishonest node, thus jepordising the 
    // the conterparties trust score.
    let honest_tranascting_ids = get_honest_nodes(transacting_reliablity, 1);
    let honest_witness_ids = get_honest_nodes(witness_reliability, 0);

    // A vector of vectors, the inner a list of the outcomes per participant from
    // the witnesses point of view.
    let mut outcomes: Vec<Vec<bool>> = vec![Vec::new(); honest_witness_ids.len()];
    for i in 0..honest_witness_ids.len() {
        let honesty_of_wn = honest_witness_ids[i];

        // witness determines the outcome for each participant
        for j in 0..honest_tranascting_ids.len() {
            let honesty_of_tn = honest_tranascting_ids[j];
            
            // if the witness node is honest, then the output is dependant on whether
            // the tn was honest. Otherwise, it is either random or a constant. They may
            // want it to random so the trust score generator has a harder time seeing
            // their dishonesty.
            if honesty_of_wn {
                outcomes[i].push(honesty_of_tn);
            } else {
                outcomes[i].push(lazy_outcome(&lazy_method));
            }
        }
    }

    //--------------------------------------------------------------
    // WITNESSES SEND THEIR STATMENTS
    //--------------------------------------------------------------

    for i in 0..witness_clients.len(){

        // WN's prepares their statement
        let wn_statement = message::Message::WitnessStatement {
            outcome: outcomes[i].clone()
        };
        let wn_statement_string = serde_json::to_string(&wn_statement)?;

        let witness_message = vec![
            wn_statement_string
        ];

        // WN sends their witness statement
        sync_all(&mut transacting_clients).await?;
        sync_all(&mut witness_clients).await?;
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
        sync_all(&mut transacting_clients).await?;
        sync_all(&mut witness_clients).await?;
        let (msg_link, _) = transacting_clients[i].send_signed_packet(
            &prev_msg_link,
            &Bytes(compensation_tx[0].as_bytes().to_vec()),
            &Bytes::default(),
        ).await?;
        println!("Sent msg from TN_{}: {}, tangle index: {:#}", i, msg_link, msg_link.to_msg_index());
        prev_msg_link = msg_link;
    }

    //--------------------------------------------------------------
    // THE PARTICIPANTS UNSUBSCRIBE SO THAT THEY CAN SUB TO OTHER CHANNELS
    //--------------------------------------------------------------

    for i in 0..transacting_clients.len() {
        transacting_clients[i].unregister();
    }
    for i in 0..witness_clients.len() {
        witness_clients[i].unregister();
    }
    
    return Ok(ann_link_string);
}
