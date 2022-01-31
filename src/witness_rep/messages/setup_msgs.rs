use crate::witness_rep::messages::transaction_msgs::{Contract};

pub struct SetupMessage {
    contract: Contract,
	max_witnesses: u32,
	payment_to_node: f32,
	max_payment_per_witness: f32,
}