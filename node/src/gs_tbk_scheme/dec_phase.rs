
use std::fs::File;
use std::io::{BufReader, BufRead, SeekFrom, Seek};
use std::path::PathBuf;

use cl_encrypt::vss::vss::integer_map_share_to_new_params;
use curv::arithmetic::traits::*;
use curv::elliptic::curves::{Secp256k1, Scalar};
pub type FE = Scalar<Secp256k1>;
use curv::BigInt;
use log::info;
use cl_encrypt::cl::clwarpper::*;
use message::node::dec_msg::NodeDecPhaseOneBroadcastMsg;
use message::proxy::dec_msg::ProxyDecPhaseOneBroadcastMsg;
use crate::node::{Node};

impl Node { 
    pub fn dec_phase_one(&self, msg:ProxyDecPhaseOneBroadcastMsg) -> NodeDecPhaseOneBroadcastMsg
    {
        let current_dir = std::env::current_dir().unwrap(); // 获取当前工作目录
        let mut input_path = PathBuf::from(current_dir.clone()); // 创建路径缓冲区并设置为当前工作目录
        let path = "src/node/node".to_string() + &self.id.unwrap().to_string() + "/keypair.txt";
        input_path.push(path.clone()); // 添加下级目录
        
        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let mut lines = reader.lines().map(|l| l.unwrap());
        // 定义两个变量来存储读取的字符串
        let pk_str = lines.next();
        info!("pk_str = {:?}", pk_str);
        let sk = lines.next();
        let pk = pre_calculate_pk(pk_str.unwrap());
        info!("pk = {:?}", pk);
        let random_str = BigInt::from_str_radix("476730434379583110068719560225079590805232138093311", 10).unwrap().to_string();
        let old_cipher = msg.old_cipher;
        let cipher = encrypt(pk, "12345".to_string(), random_str);
        let cipher_add = add_ciphertexts(old_cipher.clone(), cipher);
        let dec_c1 = decrypt_c1(cipher_add.clone(), sk.unwrap(), self.delta.to_string());
        
        NodeDecPhaseOneBroadcastMsg
        {
            sender:self.id.unwrap(),
            role:self.role.clone(),
            dec_c1,
            cipher:cipher_add
        }
    }
    pub fn dec_phase_two(&mut self, msg_vec:&Vec<NodeDecPhaseOneBroadcastMsg>)
    {
        info!("phase_two is starting");
        //verify length
        assert_eq!(msg_vec.len(), self.threashold_param.share_counts as usize);
        
        let mut lagrange_vec = Vec::new();
        for i in 0 ..= self.threashold_param.threshold as usize
        {
            lagrange_vec.push(BigInt::from(msg_vec.get(i).unwrap().sender));
        }
        
        let mut c1_total: String = get_qfi_zero();
        for i in 0 ..= self.threashold_param.threshold as usize
        {
            let msg = msg_vec.get(i).unwrap();
            let li = integer_map_share_to_new_params(BigInt::from(msg.sender), &lagrange_vec, self.threashold_param.share_counts as usize);
            info!("id: {}, li: {}", msg.sender ,li);
            let power_li = qfi_mul(msg.dec_c1.clone(), li.to_string());
            c1_total = qfi_add(c1_total, &power_li);
        }

        let m = multi_decrypt(c1_total, msg_vec.get(0).unwrap().cipher.clone(), self.delta.to_string());
        let m_bn = BigInt::from_str_radix(&m, 10).unwrap();
        let m_fe = FE::from_bigint(&m_bn);
        let delta_fe = FE::from_bigint(&self.delta);
        let delta_power_three = delta_fe.clone() * delta_fe.clone() * delta_fe.clone();
        let m_res = m_fe * delta_power_three.invert().unwrap();
        info!("m = {:?}", m_res.to_bigint());
    }
}