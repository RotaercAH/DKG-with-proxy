
use std::{path::PathBuf, io::{BufReader, BufRead}, fs::File};

use log::{info};
use message::proxy::dec_msg::{ProxyDecPhaseStartFlag, ProxyDecPhaseOneBroadcastMsg};
use crate::proxy::{Proxy};

impl Proxy 
{
    /// 生成部分公钥，随机选择参与方，然后广播给管理员
    pub fn dec_phase_one(&mut self)->(ProxyDecPhaseStartFlag, ProxyDecPhaseOneBroadcastMsg)
    {
        info!("Keygen phase is staring!");
        println!("Keygen phase is staring!");
        let flag = ProxyDecPhaseStartFlag
        {
            sender:self.id,
            role:self.role.clone(),
        };

         //读取密文
        let current_dir = std::env::current_dir().unwrap(); // 获取当前工作目录
        let mut input_path = PathBuf::from(current_dir.clone()); // 创建路径缓冲区并设置为当前工作目录
        let path = "src/proxy".to_string() + "/cipher.txt";
        input_path.push(path.clone()); // 添加下级目录
        let file_input = File::open(path.clone()).unwrap();
        let reader = BufReader::new(file_input);
        let mut old_cipher = String::new();

        if let Some(Ok(line)) = reader.lines().next() {
            old_cipher = line;
        }

        let new_message = "12345".to_string();
        let msg = ProxyDecPhaseOneBroadcastMsg{
            new_message:new_message,
            old_cipher:old_cipher
        };
        (flag,msg) 
    }
}