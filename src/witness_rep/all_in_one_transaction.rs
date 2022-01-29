use iota_streams::{
    app::transport::tangle::client::Client,
    app_channels::api::tangle::{
        Address, Author, Bytes, ChannelType, MessageContent, PublicKey, Subscriber,
        UnwrappedMessage,
    },
    core::{println, Result},
};

use crate::examples::{verify_messages, ALPH9};
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
 *  TNA and TNB both gather their witness nodes e.g. TN_A finds WN_A, and TN_B finds WNB_,
 *  then by exchangeing the witness node ids, TN_B can create a signiture for the transaction
 *  which it then sends to TN_A, whom then attaches the packet to a tangle message.
 *  TN_A then needs to send the other nodes the message index.
*/
pub async fn transact(node_url: &str) -> Result<()> {
    
    //////
    ////    PREREQUISITES 1 (CURRENT) - HAVE A NETWORK OF CLIENTS CONNECTED TO NODES
    //////

    // cloned for each node; only for testing purposes where all participants are using the same node
    let client = Client::new_from_url(node_url);

    // create participants on the simulated network
    let mut tn_a = Subscriber::new("Transacting Node A", client.clone());
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
    let ann_address = Address::from_bytes(&announcement_link.to_bytes());
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
    let sub_a_address = Address::from_bytes(&subscribe_msg_tn_a.to_bytes());
    on_a.receive_subscribe(&sub_a_address).await?;
    
    //////  **non-current stages are skipped/assumed** 
    ////    STAGE 1 - TN_A CHECKS TO SEE IF THERE ARE AVAILABLE WITNESSES (WITHOUT COMMITING TO ANYTHING)
    ////    STAGE 2 - TN_A REQUESTS TO TRANSACT WITH TN_B, TN_B ACCEPTS
    ////    STAGE 3 - TN_A AND TN_B FIND WITNESSES TO COMMIT TO THIS TRANSACTION
    ////    STAGE 4 - TN_A AND TN_B EXCHANGE WITNESSES
    ////    STAGE 5 - TN_B SIGNS THE WITNESSES+CONTRACT, SENDS THIS TO TN_A. TN_A ALSO SIGNS HIS VERSION. 
    ////    STAGE 6 - TN_A SENDS THE TRANSACTION TO ON_A FOR APPROVAL, ON_A APPROVES
    ////    STAGE 7 (CURRENT) - WITNESSES SUBSCRIBE TO CHANNEL, AUTHOR ACCEPTS
    //////
    
    // witnesses process the channel announcement
    let ann_address = Address::from_bytes(&announcement_link.to_bytes());
    wn_a.receive_announcement(&ann_address).await?;
    wn_b.receive_announcement(&ann_address).await?;
    
    // witnesses send subscription messages
    let subscribe_msg_wn_a = wn_a.send_subscribe(&ann_address).await?;
    let subscribe_msg_wn_b = wn_b.send_subscribe(&ann_address).await?;
    let sub_msg_wn_a_str = subscribe_msg_wn_a.to_string();
    let sub_msg_wn_b_str = subscribe_msg_wn_a.to_string();
    println!(
        "Subscription msgs:\n\tSubscriber WN_A: {}\n\tTangle Index: {:#}\n",
        sub_msg_wn_a_str, subscribe_msg_wn_a.to_msg_index()
    );
    println!(
        "Subscription msgs:\n\tSubscriber WN_B: {}\n\tTangle Index: {:#}\n",
        sub_msg_wn_b_str, subscribe_msg_wn_b.to_msg_index()
    );

    // Note that: sub_a = tn_a, sub_b = wn_a, sub_c = wn_b
    let sub_b_address = Address::from_bytes(&subscribe_msg_wn_a.to_bytes());
    let sub_c_address = Address::from_bytes(&subscribe_msg_wn_b.to_bytes());
    on_a.receive_subscribe(&sub_b_address).await?;
    on_a.receive_subscribe(&sub_c_address).await?;

    //////
    ////    STAGE 9  - GET THE PUBKEYS OF THE WITNESSES FROM THEM THROUGH TN_A
    ////              (BECAUSE THE PUBKEYS OF AUTHOR/SUB OBJECTS ARE DIFFERENT TO NODE PUBKEYS)
    ////    STAGE 10 (CURRENT) - ON_A SENDS A KEYLOAD FOR THIS TRANSACTION (INCLUDING TN_A AND WITNESSES)
    //////  

    // fetch subscriber public keys (for use by author in issuing a keyload);
    // we'll also use this to sort messages on the retrieval end
    let tn_a_pk = tn_a.get_public_key().as_bytes();
    let wn_a_pk = wn_a.get_public_key().as_bytes();
    let wn_b_pk = wn_b.get_public_key().as_bytes();
    let pks = vec![
        PublicKey::from_bytes(tn_a_pk)?,
        PublicKey::from_bytes(wn_a_pk)?,
        PublicKey::from_bytes(wn_b_pk)?,
    ];

    // Author sends keyload with the public keys of TN_A and witnesses to generate a new
    // branch. This will return a tuple containing the message links. The first is the
    // message link itself, the second is the sequencing message link.
    let (keyload_a_link, _seq_a_link) =
    on_a.send_keyload(&announcement_link, &vec![pks[0].into(), pks[1].into(), pks[2].into()]).await?;
    println!(
        "\nSent Keyload for TN_A and witnesses: {}, tangle index: {:#}",
        keyload_a_link,
        _seq_a_link.unwrap()
    );

    //////
    ////    STAGE 11 (CURRENT) - TN_A SENDS THE TRANSACTION ON ON_A'S CHANNEL
    //////
    
    let tx_message = vec![
        "TN_A's signed witnesses",
        "TN_B's signed witnesses",
        "..."
    ];

    let mut prev_msg_link = keyload_a_link;
    for i in 0..tx_message.len() {
        // before sending any messages, a publisher in a multi publisher channel should sync their state
        // to ensure they are up to date
        tn_a.sync_state().await;

        // TN_A sends the transaction
        let (msg_link, _) = tn_a.send_signed_packet(
            &prev_msg_link,
            &Bytes::default(),
            &Bytes(tx_message[i].as_bytes().to_vec()),
        ).await?;
        println!("Sent msg from TN_A: {}, tangle index: {:#}", msg_link, msg_link.to_msg_index());
        prev_msg_link = msg_link;
    }

    //////
    ////    STAGE 12 - WITNESSES SEE THE TRANSACTION IS UPLOADED
    ////    STAGE 13 - WITNESSES DECIDE THE PERCEIVED OUTCOME OF THE TRANSACTION AND UPDLOAD ACCORDINGLY
    ////                (DECISION BASED ON CUSTOMIZABLE FACTORS I.E. SENSORS, REPUTATION, ...)
    ////    STAGE 14 - WITNESSES UPLOAD THEIR WITNESS STATEMENTS
    //////

    let witness_a_message = vec![
        "{
            output: true,
            ...
        }"
    ];
    let witness_b_message = vec![
        "{
            output: true,
            ...
        }"
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
    println!("here");
    wn_b.sync_state().await;
    println!("here2");
    let (msg_link, _) = wn_b.send_signed_packet(
        &prev_msg_link,
        &Bytes::default(),
        &Bytes(witness_b_message[0].as_bytes().to_vec()),
    ).await?;
    println!("Sent msg from WN_B: {}, tangle index: {:#}", msg_link, msg_link.to_msg_index());
    //prev_msg_link = msg_link;

    //////
    ////    STAGE 15 - ALL PARTIES, BOTH INVOLVED AND NOT INVOLVED, CAN NOW SCAN THE TRABSACTION
    //////

    // -----------------------------------------------------------------------------
    // Author can now fetch these messages
    let mut retrieved = on_a.fetch_all_next_msgs().await;
    println!("\nAuthor found {} messages", retrieved.len());

    let mut retrieved_lists = split_retrieved(&mut retrieved, pks);
    println!("\nVerifying message retrieval: Author");
    verify_messages(&tx_message, retrieved_lists.remove(0))?;

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