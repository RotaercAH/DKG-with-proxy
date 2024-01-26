use std::collections::HashMap;


use curv::{elliptic::curves::{Secp256k1, Point, Scalar}};
use serde::{Deserialize, Serialize};


use message::params::{ThreasholdParam,Gpk, CLKeypair};
use message::proxy::setup_msg::NodeInfo;

 
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node
{
    pub id: Option<u16>,
    pub role:String,
    pub address: String, 
    pub proxy_address: String,
    pub threashold_param: ThreasholdParam,
    pub cl_keypair:CLKeypair,
    pub dkgparam: DKGParam, 
    pub gpk:Option<Gpk>,
    pub node_info_vec: Option<Vec<NodeInfo>>,
    pub participants: Option<Vec<u16>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig
{
    pub id: Option<u16>,
    pub role:String,
    pub address: String, 
    pub proxy_address: String,
    pub threashold_param: ThreasholdParam,
    pub dkgparam: DKGParam, 
    pub gpk:Option<Gpk>,
    pub node_info_vec: Option<Vec<NodeInfo>>,
    pub participants: Option<Vec<u16>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DKGParam
{
    pub ui:Option<Scalar<Secp256k1>>,
    pub yi:Option<Point<Secp256k1>>,
    pub yi_map:Option<HashMap<u16, Point<Secp256k1>>>,
    pub y:Option<Point<Secp256k1>>,
    pub mskshare: Option<Scalar<Secp256k1>>,// x_i
    pub addshare:Option<Scalar<Secp256k1>>,// x_i * li
}