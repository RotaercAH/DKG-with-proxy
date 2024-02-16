use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyDecPhaseStartFlag
{
    pub sender:u16,
    pub role:String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyDecPhaseOneBroadcastMsg{
    pub new_message:String,
    pub old_cipher:String,
}