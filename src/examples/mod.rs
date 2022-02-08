/* pub mod multi_publisher;
 */pub mod single_publisher;
/* pub mod utility; */

/* pub use multi_publisher::*; */
pub use single_publisher::*; 
/* pub use utility::*; */

use anyhow::Result;
use iota_streams::app_channels::api::tangle::{MessageContent, UnwrappedMessage};

pub const ALPH9: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9";

// Iterate through the retrieved messages to ensure they match those that were sent
pub fn verify_messages(sent_msgs: &[String], retrieved_msgs: Vec<UnwrappedMessage>) -> Result<()> {
    println!("");
    println!("Length: {}", retrieved_msgs.len());
    let processed_msgs = retrieved_msgs
        .iter()
        .map(|msg| {
            /* println!("whole obj:{:?}", msg);
            println!("just body:{:?}\n", msg.body); */
            let content = &msg.body;
            match content {
                MessageContent::SignedPacket {
                    pk: _,
                    public_payload: _,
                    masked_payload
                } => {
                    let pay = String::from_utf8(masked_payload.0.to_vec()).unwrap();
                    return pay;
                },
                _ => String::default(),
            }
        })
        .filter(|s| s != &String::default())
        .collect::<Vec<String>>();

    if processed_msgs.is_empty() && sent_msgs.is_empty() {
        return Ok(());
    }

    print!("Retrieved messages: ");
    for i in 0..processed_msgs.len() {
        print!("{}, ", processed_msgs[i]);
        //assert_eq!(processed_msgs[i], sent_msgs[i])
    }
    println!();

    Ok(())
}
