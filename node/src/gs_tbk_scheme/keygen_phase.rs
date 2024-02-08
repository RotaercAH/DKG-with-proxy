use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use anyhow::Chain;
use cl_encrypt::vss::vss::integer_share_at_indices;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::DigestExt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Secp256k1, Point, Scalar};
pub type FE = Scalar<Secp256k1>;
use curv::BigInt;
use log::info;
use sha2::{Sha256, Digest};
use num_bigint::BigUint;
use cl_encrypt::cl::clwarpper::*;
use crate::Error::{self, InvalidSS};
use message::proxy::keygen_msg::{ProxyKeyGenPhaseOneBroadcastMsg,ProxyToNodeKeyGenPhaseThreeP2PMsg,ProxyToNodesKeyGenPhasefiveBroadcastMsg};
use message::node::keygen_msg::{NodeKeyGenPhaseOneBroadcastMsg,NodeToProxyKeyGenPhaseTwoP2PMsg,ZkpProof,NodeToProxyKeyGenPhaseFiveP2PMsg, EncAndProof};
use message::params::{Gpk};
use crate::node::{Node};
use std::io::prelude::*;

impl Node { 

    /// 自选(n,n) share 的私钥碎片，计算哈希承诺并广播
    pub fn keygen_phase_one(&mut self, msg:ProxyKeyGenPhaseOneBroadcastMsg) -> NodeKeyGenPhaseOneBroadcastMsg
    {
        info!("Key is generating!");
        let gpk = Gpk
        {
            g:msg.g,
            g1:None  
        };
        self.gpk = Some(gpk);
        self.participants = Some(msg.participants);
        let secret_bound = BigInt::from_str_radix("519825222697581994973081647134787959795934971297792", 10).unwrap();
        let ui = BigInt::sample_below(&secret_bound);
        
        let yi: String = power_of_h(ui.to_string());//gp_ui
        
        self.dkgparam.ui = Some(ui);
        self.dkgparam.yi = Some(yi.clone());

        // let blind_factor = BigInt::sample(256);
        // let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
        //     &BigInt::from_bytes(yi.clone().to_bytes(true).as_ref()),
        //     &blind_factor,
        // );
        
        NodeKeyGenPhaseOneBroadcastMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            // blind_factor:blind_factor,
            yi:yi,
            // com:com,
        }
    }

    /// 验证哈希承诺，然后进行feldman vss，发送share 和 相关系数承诺   
    pub fn keygen_phase_two(&mut self, msg_vec:&Vec<NodeKeyGenPhaseOneBroadcastMsg>)
    -> Result<NodeToProxyKeyGenPhaseTwoP2PMsg, Error>
    {
        //verify length
        assert_eq!(msg_vec.len(), self.threashold_param.share_counts as usize);
        //Verify all Hashcommitment
        // let all_com_verify_tag = (0..msg_vec.len()).all( |i| {
        //     HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(&BigInt::from_bytes(msg_vec[i].yi.to_bytes(true).as_ref()), &msg_vec[i].blind_factor )== msg_vec[i].com
        // }); 
        let all_com_verify_tag = true;
        if all_com_verify_tag
        {
            // Merge and save y,y_i_map
            let mut yi_map:HashMap<u16, String> = HashMap::new();
            let mut y: String = get_qfi_zero();
            for msg in msg_vec
            {
                yi_map.insert(msg.sender, msg.yi.clone());
                y = qfi_add(y, &msg.yi.clone())
            }
            // let y:String = msg_vec.iter().map(|msg| msg.yi.clone());
            self.dkgparam.yi_map = Some(yi_map);
            self.dkgparam.y = Some(y.clone());
            info!("pk = {:?}", y);
            //将公钥写入文件
            let current_dir = std::env::current_dir().unwrap(); // 获取当前工作目录
            let mut output_path = PathBuf::from(current_dir); // 创建路径缓冲区并设置为当前工作目录
            let path = "src/node/node".to_string() + &self.id.unwrap().to_string() + "/keypair.txt";
            output_path.push(path); // 添加下级目录
            let file = File::create(output_path.clone());
            // 将字符串内容写入文件，检查是否出现错误
            match file.unwrap().write_all(y.as_bytes()) {
                Ok(_) => println!("公钥已写入文件keypair.txt"),
                Err(err) => eprintln!("写入文件时出错: {}", err),
            }

            let dkgparam = self.dkgparam.clone();
            //生成系数承诺和函数值
            let coefficients_bound = BigInt::from_str_radix("519825222697581994973081647134787959795934971297792", 10).unwrap();
            let (vss_scheme, secret_shares) =
            integer_share_at_indices(self.threashold_param.threshold, self.threashold_param.share_counts, dkgparam.ui.unwrap(), coefficients_bound.clone());
            // let shares = secret_shares.to_vec();
            let mut share_proof_map:HashMap<u16, EncAndProof> = HashMap::new();
            let mut delta = BigInt::one();
            for i in 1..=self.threashold_param.share_counts{
                delta *= BigInt::from(i);
            }
            for node in self.node_info_vec.as_ref().unwrap()
            { 
                let id = node.id; 
                // share 1~n, vec 0~n-1
                let share = &secret_shares[id as usize-1 ];
                let share_str = share.to_string();
                let random_str = BigInt::sample_below(&coefficients_bound.clone()).to_string();

                let commit_str = power_of_h(share_str.clone()); // 函数值承诺 gp ^ f(i)
                // let commit_str = to_hex(share_commit.to_bytes(true).as_ref());
                
                //加密
                let share_enc = encrypt(node.cl_pk.clone(), share_str.clone(), random_str.clone());
                //零知识证明
                let share_proof = cl_enc_com_prove(node.cl_pk.clone(), share_enc.clone(), commit_str.clone(), share_str.clone(), random_str.clone());

                let enc_and_proof = EncAndProof
                {
                    share_enc,
                    share_commit: commit_str,
                    share_proof,
                    
                };
                share_proof_map.insert(id, enc_and_proof);
            }
            Ok
            (
                NodeToProxyKeyGenPhaseTwoP2PMsg
                {
                    sender:self.id.unwrap(),
                    role:self.role.clone(),
                    share_proof_map:share_proof_map,
                    vss_scheme:vss_scheme,
                }
            )
        } 
        else
        {
            Err(Error::InvalidCom)
        }
    }

    /// 解密share，然后进行系数承诺验证
    pub fn keygen_phase_four(&mut self, msg:ProxyToNodeKeyGenPhaseThreeP2PMsg, )->Result<(), Error>
    {
        // Decrypt CL share
        let x_i = decrypt(self.cl_keypair.sk.clone(), msg.share_enc_sum);
        let mut delta = BigInt::one();
        for i in 1..=self.threashold_param.share_counts{
            delta *= BigInt::from(i);
        }
        
        if msg.vss_scheme_sum.validate_share(&BigInt::from_str_radix(&x_i, 10).unwrap(), self.id.unwrap().to_string(), &delta).is_ok()
        {
            self.dkgparam.mskshare = Some(x_i.clone());
            // info!("xi_fe is generated!");
            // info!("xi_fe = {:?}", x_i);
            //将私钥写入文件
            let current_dir = std::env::current_dir().unwrap(); // 获取当前工作目录
            let mut output_path = PathBuf::from(current_dir); // 创建路径缓冲区并设置为当前工作目录
            output_path.push("src/node/node".to_string() + &self.id.unwrap().to_string() + "/keypair.txt"); // 添加下级目录
            let mut file = OpenOptions::new().write(true).append(true).open(output_path).unwrap();
    
            // 将字符串内容写入文件，检查是否出现错误
            match file.write_all(("\n".to_string() + &x_i).as_bytes()) {
                Ok(_) => println!("私钥已写入文件 keypair.txt"),
                Err(err) => eprintln!("写入文件时出错: {}", err),
            }
            Ok(
                ()
            )
        }   
        else
        {
            Err(InvalidSS)
        }
            
    }

    /// 作零知识证明，发送proof
    pub fn keygen_phase_five(&self) -> NodeToProxyKeyGenPhaseFiveP2PMsg
    {
        let gpk = self.gpk.as_ref().unwrap();

        let t_rand = Scalar::<Secp256k1>::random();
        let g_t = &gpk.g * &t_rand;

        // challenge
        let e = Sha256::new() 
        .chain_point(&gpk.g)
        .chain_bigint(&BigInt::from_str_radix(&self.dkgparam.yi_map.as_ref().unwrap().get(&self.id.unwrap().clone()).unwrap(), 10).unwrap())
        .chain_point(&g_t)
        .result_scalar();

        // challenge response
        let z_gamma_A_i = &t_rand + &e;

        NodeToProxyKeyGenPhaseFiveP2PMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            zkp_proof:ZkpProof 
            { 
                z_gamma_A_i: z_gamma_A_i, 
                g_gamma_A_i: self.dkgparam.yi.as_ref().unwrap().clone(),
                e: e, 
                g_t: g_t, 
            },
        }
    }
    
    /// 接收然后组合出完整的GPK
    pub fn keygen_phase_six(&mut self,msg:ProxyToNodesKeyGenPhasefiveBroadcastMsg)
    {
    }

}

#[test]
fn test(){
    // let (sk,pk) = group.keygen();
    // let a = Scalar::<Bls12_381_1>::random();
    // let g = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::from(1);
    // let g_a = &g * &a;
    // //let (c,proof) = CLGroup::verifiably_encrypt(&group, &pk, (&a,&g_a));
    // let (c,_) = encrypt(&group, &pk, &a);
    // println!("{:?}",c);
}

#[test]
pub fn test1()
{
   
}



