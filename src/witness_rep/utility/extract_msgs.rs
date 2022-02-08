use iota_streams::app_channels::api::tangle::{MessageContent, UnwrappedMessage};

pub fn extract_msg(retrieved_msgs: Vec<UnwrappedMessage>) -> Vec<String> {
    
    println!("");
    println!("Length: {}", retrieved_msgs.len());
    return retrieved_msgs
            .iter()
            .map(|msg| {
                /* println!("whole obj:{:?}", msg);
                println!("just body:{:?}\n", msg.body); */
                let content = &msg.body;
                match content {
                    MessageContent::SignedPacket {
                        pk: _,
                        public_payload,
                        masked_payload: _,
                    } => {
                        let pay = String::from_utf8(public_payload.0.to_vec()).unwrap();
                        return pay;
                    },
                    _ => String::default(),
                }
            })
            .filter(|s| s != &String::default())
            .collect::<Vec<String>>();
}