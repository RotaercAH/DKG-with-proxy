use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::{elliptic::curves::{Secp256k1, Point}};
use serde::{Deserialize, Serialize};
use crate::params::{DKGTag};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyKeyGenPhaseStartFlag
{
    pub sender:u16,
    pub role:String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyKeyGenPhaseOneBroadcastMsg{
    pub g:Point<Secp256k1>,
    // pub g_hat:Point<Bls12_381_2>,
    // pub f:Point<Bls12_381_1>, 
    // pub g_sim:Point<Bls12_381_1>,
    // pub g_2:Point<Bls12_381_1>,
    // pub h_0:Point<Bls12_381_1>,
    // pub h_1:Point<Bls12_381_1>,
    // pub h_2:Point<Bls12_381_1>,
    pub participants:Vec<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToNodeKeyGenPhaseThreeP2PMsg
{
    pub dkgtag:DKGTag,
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
    // pub vk_A:Point<Bls12_381_2>,
    // pub vk_B:Point<Bls12_381_2>,
    // pub g1:Point<Bls12_381_1>,
}