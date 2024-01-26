use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::{elliptic::curves::{Secp256k1, Point}};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyKeyGenPhaseStartFlag
{
    pub sender:u16,
    pub role:String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyKeyGenPhaseOneBroadcastMsg{
    pub g:Point<Secp256k1>,
    pub participants:Vec<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodeKeyGenPhaseThreeP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub share_enc_sum:String,
    pub vss_scheme_sum:VerifiableSS<Secp256k1>,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodesKeyGenPhasefiveBroadcastMsg
{
    pub sender:u16,
    pub role:String,
}