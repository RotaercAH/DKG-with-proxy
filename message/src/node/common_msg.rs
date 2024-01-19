use serde::{Deserialize, Serialize};
use crate::node::setup_msg::{NodeToProxySetupPhaseP2PMsg, NodeSetupPhaseFinishFlag};
use crate::node::keygen_msg::{NodeKeyGenPhaseOneBroadcastMsg, NodeToProxyKeyGenPhaseFiveP2PMsg, NodeToProxyKeyGenPhaseTwoP2PMsg};
// use crate::messages::node::key_manage_msg::{NodeToProxyKeyRecoverP2PMsg, NodeToProxyKeyRefreshOneP2PMsg};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GSTBKMsg {
    SetupMsg(SetupMsg),
    KeyGenMsg(KeyGenMsg),
    // KeyManageMsg(KeyManageMsg)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SetupMsg 
{
    NodeToProxySetupPhaseP2PMsg(NodeToProxySetupPhaseP2PMsg),
    NodeSetupPhaseFinishFlag(NodeSetupPhaseFinishFlag)     
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyGenMsg {
    NodeKeyGenPhaseOneBroadcastMsg(NodeKeyGenPhaseOneBroadcastMsg),
    NodeToProxyKeyGenPhaseTwoP2PMsg(NodeToProxyKeyGenPhaseTwoP2PMsg),
    NodeToProxyKeyGenPhaseFiveP2PMsg(NodeToProxyKeyGenPhaseFiveP2PMsg)
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub enum KeyManageMsg 
// {
//     NodeToProxyKeyRecoverP2PMsg(NodeToProxyKeyRecoverP2PMsg),
//     NodeToProxyKeyRefreshOneP2PMsg(NodeToProxyKeyRefreshOneP2PMsg)
// }