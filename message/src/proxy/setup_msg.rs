// use class_group::primitives::cl_dl_public_setup::*;
use serde::{Deserialize, Serialize};
// use crate::params::PKHex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo{
    pub id: u16,// assigned id
    pub cl_pk : String,
    pub address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxySetupPhaseBroadcastMsg{
    pub node_info_vec: Vec<NodeInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxySetupPhaseFinishFlag
{
    pub sender:u16,
    pub role: String
}