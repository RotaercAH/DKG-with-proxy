use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeDecPhaseOneBroadcastMsg
{
    pub sender:u16,
    pub role:String,
    pub dec_c1:String,
    pub cipher:String
}