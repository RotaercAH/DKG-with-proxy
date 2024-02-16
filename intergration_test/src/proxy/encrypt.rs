use std::{path::PathBuf, fs::File, io::{BufReader, BufRead, Write}};

use cl_encrypt::cl::clwarpper::{pre_calculate_pk, encrypt};
use num::{BigInt, Num};

#[test]
fn test_encrypt() {
    //读取公钥
    let current_dir = std::env::current_dir().unwrap(); // 获取当前工作目录
    let mut input_path = PathBuf::from(current_dir.clone()); // 创建路径缓冲区并设置为当前工作目录
    let mut path = "src/proxy".to_string() + "/publickey.txt";
    input_path.push(path.clone()); // 添加下级目录
    let file_input = File::open(path.clone()).unwrap();
    let reader = BufReader::new(file_input);
    let mut pk_str = String::new();

    if let Some(Ok(line)) = reader.lines().next() {
        pk_str = line;
    }
    let pk = pre_calculate_pk(pk_str);
    let random_str = BigInt::from_str_radix("476730434379583110068719560225079590805232138093311", 10).unwrap().to_string();
    
    let cipher = encrypt(pk, "12345".to_string(), random_str);
    //将密文写入文件
    let mut output_path = PathBuf::from(current_dir); // 创建路径缓冲区并设置为当前工作目录
    path = "src/proxy".to_string() + "/cipher.txt";
    output_path.push(path); // 添加下级目录
    let file = File::create(output_path.clone());
    // 将字符串内容写入文件，检查是否出现错误
    match file.unwrap().write_all(cipher.as_bytes()) {
        Ok(_) => println!("公钥已写入文件publickey.txt"),
        Err(err) => eprintln!("写入文件时出错: {}", err),
    }
}