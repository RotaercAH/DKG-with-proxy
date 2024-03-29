use std::collections::HashMap;
use std::fs::{OpenOptions, File};
use std::io::Write;
use std::path::PathBuf;
use cl_encrypt::vss::vss::IntegerVss;
use curv::elliptic::curves::{Secp256k1, Point, Scalar};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{ShamirSecretSharing};
use log::{info};
use cl_encrypt::cl::clwarpper::*;
use message::proxy::keygen_msg::{ProxyKeyGenPhaseStartFlag,ProxyKeyGenPhaseOneBroadcastMsg,ProxyToNodeKeyGenPhaseThreeP2PMsg};
use message::node::keygen_msg::{NodeToProxyKeyGenPhaseTwoP2PMsg, EncAndProof};
use rand::seq::SliceRandom;
use crate::proxy::{Proxy};
use crate::Error::{self};
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
        // Verify CLDLProof
        let mut all_verify_flag = true;
        let share_proof_map_vec:Vec<HashMap<u16, EncAndProof>> = msg_vec.iter().map(|msg|msg.share_proof_map.clone()).collect();
        let vss_commitments_vec:Vec<IntegerVss> = msg_vec.iter().map(|msg|msg.vss_scheme.clone()).collect();
        
        for node in self.node_info_vec.as_ref().unwrap()
        {
            for i in 0 .. share_proof_map_vec.len(){
                let share_proof_map = share_proof_map_vec.get(i).unwrap();
                let vss_commitments = vss_commitments_vec.get(i).unwrap();
                let share_proof_info = share_proof_map.get(&node.id).unwrap();
                let proof_verify_str = cl_enc_com_verify(share_proof_info.share_proof.clone(), node.cl_pk.clone(), share_proof_info.share_enc.clone(), share_proof_info.share_commit.clone());
                // let proof_verify_str = "true";
                let commit_verify_str = vss_commitments.verify_point_commitment(node.id.to_string(), share_proof_info.share_commit.clone(), &self.delta);
                let flag;
                if proof_verify_str == "true" && commit_verify_str == "true" {flag = true;}
                else{flag = false;} 
                all_verify_flag = all_verify_flag && flag;
            }
        } 
        if all_verify_flag 
        { 
            // Merge commitment
            let vss_commitments_vec:Vec<Vec<String>> = msg_vec.iter().map(|msg|msg.vss_scheme.commitments.clone()).collect();
            let num_columns = vss_commitments_vec[0].len(); // 假设所有行的列数相同

            let mut total_vss_commitments: Vec<String> = Vec::new();
        
            for col in 0..num_columns {
                let column_result: String = vss_commitments_vec.iter().map(|row| &row[col]).fold(get_qfi_zero(), qfi_add);
                total_vss_commitments.push(column_result);
            }

           //将公钥写入文件
           let current_dir = std::env::current_dir().unwrap(); // 获取当前工作目录
           let mut output_path = PathBuf::from(current_dir); // 创建路径缓冲区并设置为当前工作目录
           let path = "src/proxy".to_string() + "/publickey.txt";
           output_path.push(path); // 添加下级目录
           let file = File::create(output_path.clone());
           // 将字符串内容写入文件，检查是否出现错误
           match file.unwrap().write_all(total_vss_commitments.get(0).unwrap().as_bytes()) {
               Ok(_) => println!("公钥已写入文件publickey.txt"),
               Err(err) => eprintln!("写入文件时出错: {}", err),
           }

            // Merge CL share
            let share_proof_map_vec:Vec<HashMap<u16, EncAndProof>> = msg_vec.iter().map(|msg| msg.share_proof_map.clone()).collect();
            let mut msg_map:HashMap<u16, ProxyToNodeKeyGenPhaseThreeP2PMsg> = HashMap::new(); 
            for node in self.node_info_vec.as_ref().unwrap()
            {
                let random = Scalar::<Secp256k1>::random().to_bigint().to_string();
                let c_zero = encrypt_enc(node.cl_pk.clone(), "0".to_string(), random.clone());
                let share_enc_sum:String = share_proof_map_vec.iter().fold(c_zero, |acc,v|{add_ciphertexts_enc(acc, v.get(&node.id).as_ref().unwrap().share_enc.clone())});
           
                msg_map.insert
                (node.id.clone(), ProxyToNodeKeyGenPhaseThreeP2PMsg
                    {
                        sender:self.id.clone(),
                        role:self.role.clone(),
                        share_enc_sum,
                        vss_scheme_sum:IntegerVss
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

}

