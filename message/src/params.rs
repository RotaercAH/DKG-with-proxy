use serde::{Deserialize, Serialize};
use curv::elliptic::curves::{Secp256k1, Point};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreasholdParam{
    pub threshold: u16,
    pub share_counts: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLKeypair
{
    pub sk:String, 
    pub pk:String
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DKGTag
{
    Gamma_A
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Gpk
{
    pub g:Point<Secp256k1>,
    pub g1:Option<Point<Secp256k1>>,
}
