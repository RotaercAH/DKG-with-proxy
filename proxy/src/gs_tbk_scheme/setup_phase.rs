// use serde::{Deserialize, Serialize};
// use std::collections::HashMap;
// use std::io::Write;
// use std::fs::File;

use crate::config::config::Config;
use crate::proxy::Proxy;
use curv::BigInt;
use message::proxy::setup_msg::{NodeInfo, ProxySetupPhaseBroadcastMsg, ProxySetupPhaseFinishFlag};
use message::node::setup_msg::{NodeToProxySetupPhaseP2PMsg, NodeSetupPhaseFinishFlag};
use log::{info};
impl Proxy{
    /// 初始化自身基本信息
    pub fn init(gs_tbk_config:Config)->Self
    {
        let mut delta = BigInt::from(1);
        for i in 1..= gs_tbk_config.threshold_params.share_counts{
            delta *= BigInt::from(i);
        }
        Self
        {
            id:0,
            role:"Proxy".to_string(),
            address:gs_tbk_config.proxy_addr,
            threashold_param:gs_tbk_config.threshold_params,
            delta:delta,
            gpk:None,
            node_info_vec:None,
            participants:None,
        }
    }
    
    /// 生成树，为管理员们分配id，然后发送树和管理员信息
    pub fn setup_phase_one(&mut self, node_setup_p2pmsg_vec:Vec<NodeToProxySetupPhaseP2PMsg>)->ProxySetupPhaseBroadcastMsg
    {
        info!("Setup phase is staring!");
        // Build tree
        let mut node_info_vec = Vec::new();
        let mut i = 1;
        for node_init_msg in node_setup_p2pmsg_vec
        {
            let node_info = NodeInfo
            {
                id:i,
                cl_pk:node_init_msg.cl_pk,
                address:node_init_msg.address,
               
            };
            node_info_vec.push(node_info);
            i = i + 1;
        }
        let setup_bromsg = ProxySetupPhaseBroadcastMsg { node_info_vec: node_info_vec};

        self.node_info_vec = Some(setup_bromsg.node_info_vec.clone());
        
        setup_bromsg
    }

    /// 结束flag
    pub fn setup_phase_two(&self, setup_finish_flag_vec:Vec<NodeSetupPhaseFinishFlag>) -> ProxySetupPhaseFinishFlag
    {
        assert_eq!(setup_finish_flag_vec.len(),self.node_info_vec.as_ref().unwrap().len());
        {
            info!("Setup phase is finished!");
            ProxySetupPhaseFinishFlag
            {
                sender:self.id,
                role:self.role.clone()
            }
        }
    }
    
}

#[test]
fn test_init_phase(){
    //Proxy::setup_phase();
}