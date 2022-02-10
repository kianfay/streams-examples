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
}


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