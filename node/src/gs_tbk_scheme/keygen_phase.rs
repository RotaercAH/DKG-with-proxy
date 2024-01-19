use std::collections::HashMap;
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
use message::params::{Gpk,DKGTag};
use crate::node::{Node,DKGParam};

impl Node { 
    /// 选择对应密钥的dkg参数
    pub fn choose_dkgparam(&self, dkgtag:&DKGTag)-> &DKGParam
    {
        let dkgparam = match dkgtag 
        {
            DKGTag::Gamma_A=>
            {
                self.dkgparams.dkgparam_A.as_ref().unwrap()
            }
        };
        dkgparam
    }
    
    /// 自选(n,n) share 的私钥碎片，计算哈希承诺并广播
    pub fn keygen_phase_one(&mut self, dkgtag:DKGTag,msg:ProxyKeyGenPhaseOneBroadcastMsg) -> NodeKeyGenPhaseOneBroadcastMsg
    {
        info!("Key {:?} is generating!",dkgtag);
        let gpk = Gpk
        {
            g:msg.g,
            g1:None  
        };
        self.gpk = Some(gpk);
        self.participants = Some(msg.participants);
        let ui = FE::random();
        let yi = self.gpk.as_ref().unwrap().g.clone() * &ui;//g_ui
        match dkgtag  
        {
            DKGTag::Gamma_A=>{ 
                self.dkgparams.dkgparam_A.as_mut().unwrap().ui = Some(ui);
                self.dkgparams.dkgparam_A.as_mut().unwrap().yi = Some(yi.clone());
            }
        }
        let blind_factor = BigInt::sample(256);
        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(yi.clone().to_bytes(true).as_ref()),
            &blind_factor,
        );
        
        NodeKeyGenPhaseOneBroadcastMsg
        {
            dkgtag:dkgtag,
            sender:self.id.unwrap(),
            role:self.role.clone(),
            blind_factor:blind_factor,
            yi:yi,
            com:com,
        }
       
    }

    /// 验证哈希承诺，然后进行feldman vss，发送share 和 相关系数承诺   
    pub fn keygen_phase_two(&mut self, msg_vec:&Vec<NodeKeyGenPhaseOneBroadcastMsg>)
    -> Result<NodeToProxyKeyGenPhaseTwoP2PMsg, Error>
    {
        //verify length
        assert_eq!(msg_vec.len(), self.threashold_param.share_counts as usize);
        let dkgtag = msg_vec[0].dkgtag.clone();
        //Verify all Hashcommitment
        let all_com_verify_tag = (0..msg_vec.len()).all( |i| {
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(&BigInt::from_bytes(msg_vec[i].yi.to_bytes(true).as_ref()), &msg_vec[i].blind_factor )== msg_vec[i].com
        }); 
        if all_com_verify_tag
        {
            // Merge and save y,y_i_map
            let mut yi_map:HashMap<u16, Point<Secp256k1>> = HashMap::new();
            for msg in msg_vec
            {
                yi_map.insert(msg.sender, msg.yi.clone());
            }
            let y:Point<Secp256k1> = msg_vec.iter().map(|msg| msg.yi.clone()).sum();
            match dkgtag  
            {
                DKGTag::Gamma_A=>{
                    self.dkgparams.dkgparam_A.as_mut().unwrap().yi_map = Some(yi_map);
                    self.dkgparams.dkgparam_A.as_mut().unwrap().y = Some(y);
                }
            }
            
            let dkgparam = self.choose_dkgparam(&dkgtag);
            //生成系数承诺和函数值
            let (vss_scheme, secret_shares) =
            VerifiableSS::share(self.threashold_param.threshold, self.threashold_param.share_counts, &dkgparam.ui.as_ref().unwrap());
            let shares = secret_shares.to_vec();
            let mut share_proof_map:HashMap<u16, EncAndProof> = HashMap::new();
            for node in self.node_info_vec.as_ref().unwrap()
            { 
                let id = node.id; 
                // share 1~n, vec 0~n-1
                let share = &shares[id as usize-1 ];
                let share_str = share.to_bigint().to_string();
                let random_str = FE::random().to_bigint().to_string();

                let share_commit = share * self.gpk.as_ref().unwrap().g.clone(); // 函数值承诺 f(i) * G
                let commit_str = to_hex(share_commit.to_bytes(true).as_ref());
                
                info!("cl_key_str in keygen {:?}", node.cl_pk.clone());
                //加密
                let share_enc = encrypt(node.cl_pk.clone(), share_str.clone(), random_str.clone());
                //零知识证明
                let share_proof = cl_ecc_prove(node.cl_pk.clone(), share_enc.clone(), commit_str, share_str.clone(), random_str.clone());

                let enc_and_proof = EncAndProof
                {
                    share_enc,
                    share_proof
                };
                share_proof_map.insert(id, enc_and_proof);
            }
            Ok
            (
                NodeToProxyKeyGenPhaseTwoP2PMsg
                {
                    dkgtag:dkgtag,
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
        let dkgtag = msg.dkgtag.clone();
        // Decrypt CL share
        let x_i = decrypt(self.cl_keypair.sk.clone(), msg.share_enc_sum);
        let mut x_i_ = String::new();
        if let Ok(decimal_num) = x_i.parse::<BigUint>() {
            x_i_ = format!("{:x}", decimal_num);
        }else{
        }
        let xi_fe = FE::from(BigInt::from_hex(x_i_.as_str()).unwrap());
        // verify coefficient commitment
        if msg.vss_scheme_sum.validate_share(&xi_fe, self.id.unwrap()).is_ok()
        {
            //println!("Sharing phase:DKGTag is {:?} vss share x{} is {}",dkgtag,self.id.unwrap(),x_i.to_bigint()); 
            match dkgtag {
                DKGTag::Gamma_A=>{
                    self.dkgparams.dkgparam_A.as_mut().unwrap().mskshare = Some(xi_fe);
                    info!("Gamma_A is generated!");
                }
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
        .chain_point(&self.dkgparams.dkgparam_A.as_ref().unwrap().yi_map.as_ref().unwrap().get(&self.id.unwrap().clone()).unwrap())
        .chain_point(&g_t)
        .result_scalar();

        // challenge response
        let z_gamma_A_i = &t_rand + &e * self.dkgparams.dkgparam_A.as_ref().unwrap().ui.as_ref().unwrap();

        NodeToProxyKeyGenPhaseFiveP2PMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            zkp_proof:ZkpProof 
            { 
                z_gamma_A_i: z_gamma_A_i, 
                g_gamma_A_i: self.dkgparams.dkgparam_A.as_ref().unwrap().yi.as_ref().unwrap().clone(),
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



