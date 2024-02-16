use curv::BigInt;
use curv::arithmetic::Samplable;
use log::info;
use curv::elliptic::curves::{Secp256k1, Scalar};
use cl_encrypt::cl::clwarpper::*;
use num::Num;
use crate::config::config::Config;
use crate::node::{Node,DKGParam};
use message::proxy::setup_msg::{ProxySetupPhaseBroadcastMsg};
use message::node::setup_msg::{NodeToProxySetupPhaseP2PMsg,NodeSetupPhaseFinishFlag};
use message::params::{CLKeypair};

pub type FE = Scalar<Secp256k1>;

impl Node{
    /// 初始化自身信息，加载配置，生成cl密钥对等
    pub fn init(gs_tbk_config:Config) -> Self
    {
        let bound = BigInt::from_str_radix("519825222697581994973081647134787959795934971297792", 10).unwrap();
        let cl_sk = BigInt::sample_range(&BigInt::from(0), &bound).to_string();
        //计算公钥
        let cl_pk = public_key_gen(cl_sk.clone());
        let cl_keypair = CLKeypair{sk:cl_sk, pk:cl_pk};
        let mut delta = BigInt::from(1);
        for i in 1..= gs_tbk_config.threshold_params.share_counts{
            delta *= BigInt::from(i);
        }
       
        Self
        {
            id:None,
            role:"Group Manager Node".to_string(),
            address:gs_tbk_config.node_addr,
            proxy_address:gs_tbk_config.proxy_addr,
            threashold_param:gs_tbk_config.threshold_params,
            cl_keypair:cl_keypair,
            delta:delta,
            dkgparam:DKGParam{ui:None,yi:None,yi_map:None,y:None,mskshare:None,addshare:None},
            gpk:None,
            node_info_vec:None,
            participants:None,
        }
        
    }

    /// 发送自己的公钥和地址给代理
    pub fn setup_phase_one(&self)->NodeToProxySetupPhaseP2PMsg
    {
        info!("Setup phase is starting!");
        NodeToProxySetupPhaseP2PMsg
        {
            role:self.role.clone(),
            cl_pk:self.cl_keypair.pk.clone(),
            address:self.address.clone(),
        }

    }

    /// 存储所有管理员的基本信息，公钥，id，地址等等
    pub fn setup_phase_two(&mut self, msg:ProxySetupPhaseBroadcastMsg)-> NodeSetupPhaseFinishFlag
    {
        for node in msg.node_info_vec.iter()
        {
            if node.address == self.address
            {
                self.id = Some(node.id);
            }
        }
        self.node_info_vec = Some(msg.node_info_vec);
        NodeSetupPhaseFinishFlag 
        { 
            sender: self.id.unwrap(), 
            role:self.role.clone(),
        }
    }

    pub fn setup_phase_three(&self)
    {
        info!("Setup phase is finished!")
    }
 
}


#[test]
fn test()
{
}