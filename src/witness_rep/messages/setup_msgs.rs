use crate::witness_rep::messages::transaction_msgs::{Contract};

pub struct SetupMessage {
    pub contract: Contract,
	pub max_witnesses: u32,
	pub payment_to_node: f32,
	pub max_payment_per_witness: f32,
}