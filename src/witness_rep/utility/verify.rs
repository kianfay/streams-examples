use anyhow::Result;
use iota_streams::app_channels::api::tangle::{UnwrappedMessage};

use crate::witness_rep::utility::extract_msgs;

pub fn verify_messages(sent_msgs: &[String], retrieved_msgs: Vec<UnwrappedMessage>) -> Result<()> {
    let processed_msgs = extract_msgs::extract_msg(retrieved_msgs);

    if processed_msgs.is_empty() && sent_msgs.is_empty() {
        return Ok(());
    }

    print!("Retrieved messages: ");
    for i in 0..processed_msgs.len() {
        print!("{:?}, ", processed_msgs[i]);
        assert_eq!(processed_msgs[i], sent_msgs[i])
    }
    println!();

    Ok(())
}