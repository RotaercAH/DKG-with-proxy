use serde::{Deserialize, Serialize};

use crate::proxy::setup_msg::{ProxySetupPhaseBroadcastMsg,ProxySetupPhaseFinishFlag};
use crate::proxy::keygen_msg::{ProxyKeyGenPhaseOneBroadcastMsg,ProxyToNodeKeyGenPhaseThreeP2PMsg,ProxyKeyGenPhaseStartFlag};

use super::dec_msg::{ProxyDecPhaseOneBroadcastMsg, ProxyDecPhaseStartFlag};
// use crate::messages::proxy::key_manage_msg::{ProxyToNodeKeyRefreshPhaseTwoP2PMsg,ProxyToNodeKeyRefreshPhaseStartFlag,ProxyToNodeKeyRocoverPhseStartFlag};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GSTBKMsg {
    SetupMsg(SetupMsg),
    KeyGenMsg(KeyGenMsg),
    DecMsg(DecMsg)
    // KeyManageMsg(KeyManageMsg)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SetupMsg 
{
    ProxySetupPhaseBroadcastMsg(ProxySetupPhaseBroadcastMsg), 
    ProxySetupPhaseFinishFlag(ProxySetupPhaseFinishFlag)     
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyGenMSKFlag {
    GammaA(KeyGenMsg),
    GammaB(KeyGenMsg),
    GammaO(KeyGenMsg),
    GammaC(KeyGenMsg)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyGenMsg {
    ProxyKeyGenPhaseStartFlag(ProxyKeyGenPhaseStartFlag),
    ProxyKeyGenPhaseOneBroadcastMsg(ProxyKeyGenPhaseOneBroadcastMsg),
    ProxyToNodeKeyGenPhaseThreeP2PMsg(ProxyToNodeKeyGenPhaseThreeP2PMsg)
    // ProxyKeyGenPhasefiveBroadcastMsg(ProxyKeyGenPhasefiveBroadcastMsg)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DecMsg {
    ProxyDecPhaseOneBroadcastMsg(ProxyDecPhaseOneBroadcastMsg),
    ProxyDecPhaseStartFlag(ProxyDecPhaseStartFlag)
}
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub enum KeyManageMsg 
// {
//     ProxyToNodeKeyRocoverPhseStartFlag(ProxyToNodeKeyRocoverPhseStartFlag),
//     ProxyToNodeKeyRefreshPhaseStartFlag(ProxyToNodeKeyRefreshPhaseStartFlag),
//     ProxyToNodeKeyRefreshPhaseTwoP2PMsg(ProxyToNodeKeyRefreshPhaseTwoP2PMsg)    
// }