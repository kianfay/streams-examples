use crate::witness_rep::{
    iota_did::create_and_upload_did::{
        create_n_dids, Key
    },
    messages::{
        message, setup_msgs,
        signatures, transaction_msgs
    },
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


pub struct ParticipantIdentity {
    channel_client: Subscriber<Client>,
    did_keypair: KeyPair
}

pub struct OrganizationIdentity {
    channel_client: Author<Client>,
    did_keypair: KeyPair
}

pub async fn transact<'a>(
    mut transacting_nodes: Vec<ParticipantIdentity>,
    mut witness_nodes: Vec<ParticipantIdentity>,
    mut organization_node: OrganizationIdentity
) -> Result<()> {

    //--------------------------------------------------------------
    //--------------------------------------------------------------
    // EXTRACT CLIENTS FROM THE PARAMETERS
    //--------------------------------------------------------------

    // extract the transacting node's clients from the ids
    //let transacting_clients: &'a Vec<&'a mut Subscriber<Client>> = get_clients(transacting_nodes);

    //let witness_clients: &'a Vec<&'a mut Subscriber<Client>> = get_clients(witness_nodes);
    
    // extract the organization id's client

    //--------------------------------------------------------------
    // 
    //--------------------------------------------------------------

    // the organization node creates branch by sending custom keyload
    // (due to bugs, done by creating a new channel)

    match organization_node {
        OrganizationIdentity {
            mut channel_client,
            did_keypair: _
        } => {
            let announcement_link = channel_client.send_announce().await?;
            let ann_link_string = announcement_link.to_string();
            println!(
                "Announcement Link: {}\nTangle Index: {:#}\n",
                ann_link_string, announcement_link.to_msg_index()
            );
        }
    }

    

    
    
    return Ok(());
}

/* pub fn get_clients<'a>(parts: Vec<&'a Participant>) -> &'a Vec<&'a mut Subscriber<Client>> {
    // extract the transacting node's clients from the ids
    let mut clients: Vec<&'a mut Subscriber<Client>> = Vec::new();
    parts
        .iter()
        .map(|Participant(Identity{mut channel_client, did_keypair:_})|  {
            clients.push(&mut channel_client);
        });
    return &clients;
} */