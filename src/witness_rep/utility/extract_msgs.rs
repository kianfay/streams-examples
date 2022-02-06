use iota_streams::app_channels::api::tangle::{MessageContent, UnwrappedMessage};

pub fn extract_msg(retrieved_msgs: Vec<UnwrappedMessage>) -> Vec<String> {
    return retrieved_msgs
            .iter()
            .map(|msg| {
                let content = &msg.body;
                match content {
                    MessageContent::SignedPacket {
                        pk: _,
                        public_payload,
                        masked_payload: _,
                    } => String::from_utf8(public_payload.0.to_vec()).unwrap(),
                    _ => String::default(),
                }
            })
            .filter(|s| s != &String::default())
            .collect::<Vec<String>>();
}