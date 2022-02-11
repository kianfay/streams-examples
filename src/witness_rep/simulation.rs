use crate::witness_rep::{
    iota_did::create_and_upload_did::create_n_dids,
    messages::transaction_msgs,
    transaction::transaction,
    utility::verify_tx
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
use std::collections::BTreeSet;

// For now this simulation is capturing the abstract scenario where the initiating participant wishes 
// to informally buy something from somebody nearby. However, not all people around them are particpants
// of the system he uses. Therefore, the average_proximity paramater is included. This  represents the
// chance a participant being in range of some other participant.
// 
// Params:
//      - average_proximity: [0,1], 1 meaning all participants are in range
//      - witness_floor: the minimum number of witnesses in a transaction
pub async fn simulation(node_url: &str, num_participants: usize, average_proximity: f32, witness_floor: usize) -> Result<()> {

    //--------------------------------------------------------------
    //--------------------------------------------------------------
    // CREATE PARTICIPANTS FOR SIMULATION
    // (MORE DETAILS IN ALL_IN_ONE_TRANSACTION.RS)
    //--------------------------------------------------------------
    
    // create Decentalised Ids (for now, none needed for the organization)
    let did_details = create_n_dids(num_participants).await?;
    
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
    let participants: &mut Vec<Subscriber<Client>> = &mut Vec::new();
    for i in 0..num_participants{
        let name = format!("Participant {}", i);
        let tn = Subscriber::new(&name, client.clone());
        participants.push(tn);
    }

    // generate channel author instance
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
    // GENERATE GROUPS OF TRANSACATING NODES AND WITNESSES
    //--------------------------------------------------------------

    let transacting_clients: &mut Vec<Subscriber<Client>> = &mut Vec::new();
    let witness_clients: &mut Vec<Subscriber<Client>> = &mut Vec::new();

    // we select the initiating transacting participant as the first participant
    transacting_clients.push(participants.remove(0));
    
    // The initiating transacting participant searches for another to transact with.
    // Using mod, this section will only finish when one is found, representing the start
    // of the process
    let mut count = 0;
    loop {
        if average_proximity > rand::thread_rng().gen() {
            transacting_clients.push(participants.remove(count % participants.len()));
            break;
        }
        count = count + 1;
    }

    // The transacting participants now search for witnesses and combine their results.
    // Each iteration of the upper loop is one of the transacting nodes searching for
    // witnesses. We must work with indexes instead of actual objects to avoid dublicate
    // versions of the same object, not that Rust would allow that...
    let tn_witnesses_lists: &mut Vec<Vec<usize>> = &mut Vec::new();

    for i in 0..transacting_clients.len(){
        println!("getting {}th witnesses", i);
        let mut tn_witnesses: Vec<usize> = Vec::new();
        for j in 0..participants.len(){
            let rand: f32 = rand::thread_rng().gen();
            println!("Trying participant {}. Rand={}", j, rand);
            if average_proximity > rand {
                tn_witnesses.push(j);
            }
        }
        println!("Found witnesses: {:?}", tn_witnesses);
        tn_witnesses_lists.push(tn_witnesses);
    }

    // The transacting participants combine their witnesses, and check if there are enough.
    // Using BTreeSet because it is ordered
    let mut set_of_witnesses: BTreeSet<&mut usize> = BTreeSet::new();
    for witnesses in tn_witnesses_lists{
        for witness in witnesses{
            set_of_witnesses.insert(witness);
        }
    }

    if set_of_witnesses.len() < witness_floor {
        panic!("Not enough witnesses were generated.")
    }

    // convert indices into objects (as it is ordered, we can account for
    // the changing indices)
    for (i, witness) in set_of_witnesses.iter().enumerate() {
        witness_clients.push(participants.remove(**witness - i))
    }

    //--------------------------------------------------------------
    // GENERATE CONTRACT
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
    let annoucement_msg = transaction::transact(
        contract_hardcoded,
        transacting_clients,
        witness_clients,
        did_kps[0..2].to_vec(),
        did_kps[2..4].to_vec(),
        &mut on_a,
        did_kps[4]
    ).await?;

    verify_tx::verify_txs(node_url, annoucement_msg).await?;

    return Ok(());

}