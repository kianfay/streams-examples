use serde::{Deserialize, Serialize};

//////
////	STRUCTURES
//////

#[derive(Serialize, Deserialize, Clone)]
pub struct WitnessStatement {
    pub outcome: bool
}