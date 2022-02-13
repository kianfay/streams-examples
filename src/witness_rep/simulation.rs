use crate::witness_rep::{
    iota_did::create_and_upload_did::{create_n_dids, Key},
    transaction::generate_contract,
    transaction::transaction::{transact, ParticipantIdentity, LazyMethod},
    utility::verify_tx,
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
use std::convert::TryInto;

// For now this simulation is capturing the abstract scenario where the initiating participant wishes 
// to informally buy something from somebody nearby. However, not all people around them are particpants
// of the system he uses. Therefore, the average_proximity paramater is included. This  represents the
// chance a participant being in range of some other participant.
// 
// Params:
//      - average_proximity: [0,1], 1 meaning all participants are in range
//      - witness_floor: the minimum number of witnesses in a transaction
pub async fn simulation(
    node_url: &str,
    num_participants: usize,
    average_proximity: f32,
    witness_floor: usize,
    runs: usize,
    reliability: Vec<f32>
) -> Result<()> {

    if reliability.len() != num_participants {
        panic!("Number of elements in 'reliability' parameter must equal the num_participants!")
    }
    //--------------------------------------------------------------
    //--------------------------------------------------------------
    // CREATE PARTICIPANTS FOR SIMULATION
    // (MORE DETAILS IN ALL_IN_ONE_TRANSACTION.RS)
    //--------------------------------------------------------------
    
    // create Decentalised Ids (for now, none needed for the organization)
    let did_details = create_n_dids(num_participants).await?;
    
    let did_kps : Vec<Key> = did_details
                                            .iter()
                                            .map(|(_, (_,(_, privkey)), _)| *privkey)
                                            .collect();

    // create channel subscriber instances
    let client = Client::new_from_url(node_url);
    let participants: &mut Vec<ParticipantIdentity> = &mut Vec::new();
    for i in 0..num_participants{
        let name = format!("Participant {}", i);
        let tn = Subscriber::new(&name, client.clone());
        let id = ParticipantIdentity {
            channel_client: tn,
            did_key: did_kps[i],
            reliability: reliability[i]
        };
        participants.push(id);
    }

    //--------------------------------------------------------------
    // RUN SIMULATION
    //--------------------------------------------------------------

    // generate the lazy methods (currenlty the first half are 
    // constant true and the second half are random)
    let lazy_methods: Vec<LazyMethod> = (0..=runs)
        .map(|x| {
            if x > runs/2 {
                LazyMethod::Constant(true)
            } else {
                LazyMethod::Random
            }
        }).collect::<Vec<LazyMethod>>()
        .try_into().expect("wrong size iterator");

    for i in 0..runs {
        simulation_iteration(
            node_url, client.clone(),
            participants,
            average_proximity,
            witness_floor,
            lazy_methods[i].clone()
        ).await?;
    }

    return Ok(());
}


// Runs a single iteration of a simualtion
pub async fn simulation_iteration(
    node_url: &str,
    client: Client,
    mut participants: &mut Vec<ParticipantIdentity>,
    average_proximity: f32,
    witness_floor: usize,
    lazy_method: LazyMethod
) -> Result<()> {

    //--------------------------------------------------------------
    // NEEDS A NEW AUTHOR TO CREATE A NEW CHANNEL
    //--------------------------------------------------------------
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
    // GENERATE GROUPS OF TRANSACATING NODES AND WITNESSES 1
    //--------------------------------------------------------------

    let (mut transacting_clients, mut witness_clients) = generate_trans_and_witnesses(&mut participants, average_proximity, witness_floor)?;

    //--------------------------------------------------------------
    // GENERATE CONTRACT
    //--------------------------------------------------------------

    let contract = generate_contract::generate_contract(&mut transacting_clients)?;

    //--------------------------------------------------------------
    // PERFORM THE TRANSACTION WITH CONTRACT
    //--------------------------------------------------------------

    let annoucement_msg = transact(
        contract,
        &mut transacting_clients,
        &mut witness_clients,
        &mut on_a,
        lazy_method
    ).await?;

    // put the particpants back into the original array
    participants.append(&mut transacting_clients);
    participants.append(&mut witness_clients);

    // verify the transaction
    verify_tx::verify_txs(node_url, annoucement_msg, seed).await?;

    return Ok(());
}

// Generates the transacting nodes and the witnesses for the next simulation
pub fn generate_trans_and_witnesses(
    participants: &mut Vec<ParticipantIdentity>,
    average_proximity: f32,
    witness_floor: usize
) -> Result<(Vec<ParticipantIdentity>,Vec<ParticipantIdentity>)> {

    let mut transacting_clients_1: Vec<ParticipantIdentity> = Vec::new();
    let mut witness_clients_1: Vec<ParticipantIdentity> = Vec::new();

    // we select the initiating transacting participant as the first participant
    transacting_clients_1.push(participants.remove(0));
    
    // The initiating transacting participant searches for another to transact with.
    // Using mod, this section will only finish when one is found, representing the start
    // of the process
    let mut count = 0;
    loop {
        if average_proximity > rand::thread_rng().gen() {
            transacting_clients_1.push(participants.remove(count % participants.len()));
            break;
        }
        count = count + 1;
    }

    // The transacting participants now search for witnesses and combine their results.
    // Each iteration of the upper loop is one of the transacting nodes searching for
    // witnesses. We must work with indexes instead of actual objects to removing potential
    // witnesses from the list for transacting nodes of indices larger than 0
    let tn_witnesses_lists: &mut Vec<Vec<usize>> = &mut Vec::new();

    for i in 0..transacting_clients_1.len(){
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
        witness_clients_1.push(participants.remove(**witness - i))
    }

    return Ok((transacting_clients_1, witness_clients_1));
}