use std::collections::HashMap;
use curv::elliptic::curves::{Point, Secp256k1, Scalar};
use serde::{Deserialize, Serialize};
use curv::BigInt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use crate::params::{DKGTag};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeKeyGenPhaseOneBroadcastMsg
{
    pub dkgtag:DKGTag,
    pub sender:u16,
    pub role:String,
    pub blind_factor:BigInt,
    pub yi:Point<Secp256k1>,
    pub com:BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncAndProof
{
    pub share_enc:String,
    pub share_proof:String
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyKeyGenPhaseTwoP2PMsg
{//p to p
    pub dkgtag:DKGTag,
    pub sender:u16,
    pub role:String,
    pub share_proof_map:HashMap<u16, EncAndProof>,
    pub vss_scheme:VerifiableSS<Secp256k1>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkpProof
{
    pub z_gamma_A_i:Scalar<Secp256k1>,
    pub g_gamma_A_i:Point<Secp256k1>,
    pub e:Scalar<Secp256k1>,
    pub g_t:Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeToProxyKeyGenPhaseFiveP2PMsg
{
    pub sender:u16,
    pub role:String,
    pub zkp_proof:ZkpProof,
}
