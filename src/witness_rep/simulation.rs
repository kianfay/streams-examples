use crate::witness_rep::{
    iota_did::create_and_upload_did::{
        create_n_dids, Key
    },
    messages::{
        message, setup_msgs,
        signatures, transaction_msgs
    },
    transaction::transaction
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

pub async fn simulation(node_url: &str) -> Result<()> {

    //--------------------------------------------------------------
    //--------------------------------------------------------------
    // CREATE PARTICIPANTS FOR SIMULATION
    // (MORE DETAILS IN ALL_IN_ONE_TRANSACTION.RS)
    //--------------------------------------------------------------
    let client = Client::new_from_url(node_url);

    let mut tn_a = Subscriber::new("Transacting Node A", client.clone());
    let mut tn_b = Subscriber::new("Transacting Node B", client.clone());
    let mut wn_a = Subscriber::new("Witness Node A", client.clone());
    let mut wn_b = Subscriber::new("Witness Node B", client.clone());

    let did_details = create_n_dids(5).await?;
    
    let did_kps : Vec<&KeyPair> = did_details
                                            .iter()
                                            .map(|(_, (kp,_), _)| kp)
                                            .collect();

    let tn_a_id = transaction::ParticipantIdentity{
        channel_client: tn_a.export("pass").await?,
        did_keypair: did_kps[0].clone()
    };
    let tn_b_id = transaction::ParticipantIdentity{
        channel_client: tn_b.export("pass").await?,
        did_keypair: did_kps[1].clone()
    };
    let wn_a_id = transaction::ParticipantIdentity{
        channel_client: wn_a.export("pass").await?,
        did_keypair: did_kps[2].clone()
    };
    let wn_b_id = transaction::ParticipantIdentity{
        channel_client: wn_b.export("pass").await?,
        did_keypair: did_kps[3].clone()
    };

    let transacting_nodes = vec![tn_a_id, tn_b_id];
    let witness_nodes = vec![wn_a_id, wn_b_id];        

    let seed: &str = &(0..81)
        .map(|_| {
            ALPH9
                .chars()
                .nth(rand::thread_rng().gen_range(0, 27))
                .unwrap()
        })
        .collect::<String>();
    
    let mut on_a = Author::new(seed, ChannelType::SingleBranch, client.clone()).export("pass").await?;
    let on_a_id = transaction::OrganizationIdentity {
        channel_client: on_a,
        did_keypair: did_kps[4].clone()
    };

    transaction::transact(transacting_nodes, witness_nodes, on_a_id, client.clone());

    return Ok(());

}