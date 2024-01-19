use std::collections::HashMap;
use curv::elliptic::curves::{Secp256k1, Point, Scalar};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{VerifiableSS,ShamirSecretSharing};
use log::{info};
use cl_encrypt::cl::clwarpper::*;
use message::proxy::keygen_msg::{ProxyKeyGenPhaseStartFlag,ProxyKeyGenPhaseOneBroadcastMsg,ProxyToNodeKeyGenPhaseThreeP2PMsg,ProxyToNodesKeyGenPhasefiveBroadcastMsg};
use message::node::keygen_msg::{NodeToProxyKeyGenPhaseTwoP2PMsg,NodeToProxyKeyGenPhaseFiveP2PMsg, EncAndProof};
use rand::seq::SliceRandom;
use crate::proxy::{Proxy};
use crate::Error::{self,InvalidSS};
use message::params::{Gpk};  

impl Proxy 
{
    /// 生成部分公钥，随机选择参与方，然后广播给管理员
    pub fn keygen_phase_one(&mut self)->(ProxyKeyGenPhaseStartFlag, ProxyKeyGenPhaseOneBroadcastMsg)
    {
        info!("Keygen phase is staring!");
        println!("Keygen phase is staring!");
        let flag = ProxyKeyGenPhaseStartFlag
        {
            sender:self.id,
            role:self.role.clone(),
        };

        let g = Point::<Secp256k1>::generator() * Scalar::<Secp256k1>::from(1);

        let node_id_vec:Vec<u16> = self.node_info_vec.as_ref().unwrap().iter().map(|node|node.id).collect();
        // 随机选择参与节点
        let mut rng = rand::thread_rng();
        let participants:Vec<u16> = node_id_vec.choose_multiple(&mut rng,(self.threashold_param.threshold + 1) as usize).cloned().collect();
        self.participants = Some(participants.clone());
        self.gpk = Some(Gpk{
            g:g.clone(),
            g1:None
        });
        let msg = ProxyKeyGenPhaseOneBroadcastMsg{
            g:g,
            participants:participants
        };
        (flag,msg) 
    }

    /// 验证 CLDLProof 然后合并系数承诺和share碎片
    pub fn keygen_phase_three(&self,msg_vec:Vec<NodeToProxyKeyGenPhaseTwoP2PMsg>) -> Result<HashMap<u16, ProxyToNodeKeyGenPhaseThreeP2PMsg>,Error>
    {
        assert_eq!(msg_vec.len(), self.threashold_param.share_counts as usize);
        let dkgtag = msg_vec[0].dkgtag.clone();
        // Verify CLDLProof
        let mut all_verify_flag = true;
        let share_proof_map_vec:Vec<HashMap<u16, EncAndProof>> = msg_vec.iter().map(|msg|msg.share_proof_map.clone()).collect();
        let vss_commitments_vec:Vec<VerifiableSS<Secp256k1>> = msg_vec.iter().map(|msg|msg.vss_scheme.clone()).collect();
        for node in self.node_info_vec.as_ref().unwrap()
        {
            for i in 0 .. share_proof_map_vec.len(){
                let share_proof_map = share_proof_map_vec.get(i).unwrap();
                let vss_commitments = vss_commitments_vec.get(i).unwrap();
                let commit_str = to_hex(vss_commitments.get_point_commitment(node.id).to_bytes(true).as_ref());
                let share_proof_info = share_proof_map.get(&node.id).unwrap();
                let flag_str = cl_ecc_verify(share_proof_info.share_proof.clone(), node.cl_pk.clone(), share_proof_info.share_enc.clone(), commit_str);
                let flag;
                if flag_str == "true" {flag = true;} 
                else{flag = false;} 
                info!("verify is {:?}", flag_str);
                all_verify_flag = all_verify_flag && flag;
            }
        } 
        if all_verify_flag 
        { 
            // Merge commitment
            let vss_commitments_vec:Vec<Vec<Point<Secp256k1>>> = msg_vec.iter().map(|msg|msg.vss_scheme.commitments.clone()).collect();
            let total_vss_commitments = vss_commitments_vec
            .iter()
            .fold(vec![Point::<Secp256k1>::zero();vss_commitments_vec.len()], |acc,v| 
                { 
                    acc.iter()
                    .zip(v.iter())
                    .map(|(a,b)| a+b)
                    .collect()
                }
            );
            
            // Merge CL share
            let share_proof_map_vec:Vec<HashMap<u16, EncAndProof>> = msg_vec.iter().map(|msg| msg.share_proof_map.clone()).collect();
            let mut msg_map:HashMap<u16, ProxyToNodeKeyGenPhaseThreeP2PMsg> = HashMap::new(); 
            for node in self.node_info_vec.as_ref().unwrap()
            {
                let random = Scalar::<Secp256k1>::random().to_bigint().to_string();
                let c_zero = encrypt(node.cl_pk.clone(), "0".to_string(), random.clone());
                // let (c_zero,_) = encrypt(&group, &hex_to_pk(&node.pk_hex), &Scalar::<Bls12_381_1>::zero());
                let share_enc_sum:String = share_proof_map_vec.iter().fold(c_zero, |acc,v|{add_ciphertexts(acc, v.get(&node.id).as_ref().unwrap().share_enc.clone())});
                msg_map.insert
                (node.id.clone(), ProxyToNodeKeyGenPhaseThreeP2PMsg
                    {
                        dkgtag:dkgtag.clone(),
                        sender:self.id.clone(),
                        role:self.role.clone(),
                        share_enc_sum,
                        vss_scheme_sum:VerifiableSS 
                        { 
                            parameters: 
                            ShamirSecretSharing 
                            { 
                                threshold: self.threashold_param.threshold, 
                                share_count: self.threashold_param.share_counts 
                            }, 
                            commitments: total_vss_commitments.clone() 
                        }
                    }
                );
            }
            Ok(msg_map)
        }
        else  
        { 
            Err(Error::InvalidZkp)
        }
    }

    /// 验证零知识证明，然后组合出完整的GPK
    pub fn keygen_phase_five(&mut self,msg_vec:Vec<NodeToProxyKeyGenPhaseFiveP2PMsg>)
    ->Result<ProxyToNodesKeyGenPhasefiveBroadcastMsg,Error>
    {
        assert_eq!(msg_vec.len(), self.threashold_param.share_counts as usize);
        // Verify zkp
        let gpk = self.gpk.clone().unwrap();
        let mut all_zkp_flag = true;
        for msg in &msg_vec
        {
            let g_z_gamma_A = &gpk.g * &msg.zkp_proof.z_gamma_A_i;
            let flag = if (
                (g_z_gamma_A == &msg.zkp_proof.g_t + &msg.zkp_proof.g_gamma_A_i * &msg.zkp_proof.e)
            )
            {
                true
            }
            else
            {
                false
            };
            all_zkp_flag = all_zkp_flag && flag;
        };

        if all_zkp_flag
        {
            info!("Keygen phase is finished!");
            println!("Keygen phase is finished!");
            Ok(
                ProxyToNodesKeyGenPhasefiveBroadcastMsg
                {
                    sender:self.id,
                    role:self.role.clone()
                }
            )
        }
        else 
        {
            Err(InvalidSS)      
        }
        

    }

}
