use iota_streams::app_channels::api::tangle::{
    MessageContent, UnwrappedMessage
};
use identity::{
    did::MethodData
};

// Ectracts all message payloads and pubkeys
pub fn extract_msg(retrieved_msgs: Vec<UnwrappedMessage>) -> Vec<(String, String)> {
    
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
                        pk,
                        public_payload,
                        masked_payload: _,
                    } => {
                        let pay = String::from_utf8(public_payload.0.to_vec()).unwrap();
                        println!("{}", pay);
                        let pubk = MethodData::new_multibase(pk);
                        if let MethodData::PublicKeyMultibase(mbpub) = pubk {
                            return (pay, mbpub);
                        } else {
                            let empty_str = String::default();
                            return (empty_str.clone(), empty_str.clone());
                        }
                        
                    },
                    _ => {
                        let empty_str = String::default();
                        return (empty_str.clone(), empty_str.clone());
                    }
                }
            })
            .filter(|(s1, s2)| s1 != &String::default() || s2 != &String::default())
            .collect::<Vec<(String,String)>>();
}