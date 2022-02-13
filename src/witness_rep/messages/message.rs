use crate::witness_rep::messages::transaction_msgs;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Message{
    WitnessStatement {
        outcome: Vec<bool>
    },
    TransactionMsg {
        contract: transaction_msgs::Contract,
        witnesses: transaction_msgs::WitnessClients,
        wit_node_sigs: transaction_msgs::ArrayOfWnSignitures,
        tx_client_sigs: transaction_msgs::ArrayOfTxSignitures,
    },
    CompensationMsg {
        payments: Vec<String>
    }
}