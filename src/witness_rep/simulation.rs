use crate::witness_rep::{
    iota_did::create_and_upload_did::create_n_dids,
    messages::transaction_msgs,
    transaction::transaction
};
use crate::examples::{ALPH9};

use iota_streams::{
    app::transport::tangle::client::Client,
    app_channels::api::tangle::{
        Author, ChannelType, Subscriber,
    },
    core::Result
};
use identity::{
    did::MethodData,
    crypto::KeyPair
};
use rand::Rng;

pub async fn simulation(node_url: &str) -> Result<()> {

    //--------------------------------------------------------------
    //--------------------------------------------------------------
    // CREATE PARTICIPANTS FOR SIMULATION
    // (MORE DETAILS IN ALL_IN_ONE_TRANSACTION.RS)
    //--------------------------------------------------------------
    
    // create Decentalised Ids (first 4 are participants, 5th is organization)
    let did_details = create_n_dids(5).await?;
    
    let did_kps : Vec<&KeyPair> = did_details
                                            .iter()
                                            .map(|(_, (kp,_), _)| kp)
                                            .collect();

    let did_pubkeys : Vec<String> = did_details
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

    // create channel subscriber instances
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
    
    let mut on_a = Author::new(seed, ChannelType::SingleBranch, client.clone());

    //--------------------------------------------------------------
    // GENERATE CONTRACT 1
    //--------------------------------------------------------------

    // TODO

    let contract_hardcoded = transaction_msgs::Contract {
        contract_definition: String::from("tn_b allows tn_a to enter in front of it in the lane tn_b is in"),               
        participants: transaction_msgs::TransactingClients(
            Vec::from([did_pubkeys[0].clone(), did_pubkeys[1].clone()])
        ),      
        time: 1643572739,
        location: ((53, 20, 27.036),(6, 15, 2.695)),
    };

    //--------------------------------------------------------------
    // PERFORM THE TRANSACTION WITH CONTRACT 1
    //--------------------------------------------------------------

    //transaction::transact(transacting_nodes, witness_nodes, on_a_id, client.clone());
    transaction::transact(
        contract_hardcoded,
        transacting_clients,
        witness_clients,
        did_kps[0..2].to_vec(),
        did_kps[2..4].to_vec(),
        &mut on_a,
        did_kps[4]
    ).await?;

    return Ok(());

}