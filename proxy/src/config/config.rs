use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use message::params::ThreasholdParam;

#[derive(Debug, Deserialize)]
pub struct Config 
{
    pub proxy_addr: String,
    pub threshold_params: ThreasholdParam,
}

impl Config{
    pub fn load_config(path:&str)->String{
        let mut config_file = File::open(path).expect("Fail to open file!");
        let mut config_str = String::new();
        config_file.read_to_string(&mut config_str).expect("Fail to read file contents");
        config_str
    }
}

#[test]
fn test_load_config() 
{
    println!("{:?}",std::env::current_dir());
    let path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/config/config_files/gs_tbk_config.json";
    println!("{:?}",path);
    println!("{:?}",Config::load_config(&path));
    
    
}