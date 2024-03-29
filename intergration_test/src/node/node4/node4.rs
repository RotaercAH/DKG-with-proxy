use message::node::dec_msg::NodeDecPhaseOneBroadcastMsg;
use tokio::net::{TcpListener};
use tokio::sync::Mutex as TokioMutex;
use tokio_util::codec::{Framed, LinesCodec};
use std::net::SocketAddr;
use std::sync::Arc;
use std::env;
use log::{error, info};
use node::communication::communication::*;
use node::node::{Node};
use node::config::config::Config;
use message::common_msg::GSTBKMsg;
use message::node::keygen_msg::{NodeKeyGenPhaseOneBroadcastMsg, NodeKeyGenPhaseFiveBroadcastMsg};
use message::node::common_msg::{SetupMsg, KeyGenMsg, DecMsg};


#[tokio::main]
pub async fn decrypt() -> Result<(), anyhow::Error> 
{
    // 初始化 日志记录器
    let log_path = String::from(env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/node/node4/config/config_file/log4rs.yaml";
    log4rs::init_file(log_path, Default::default()).unwrap();
    
    //初始化node
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/node/node4/config/config_file/node_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();

    //将node设置成共享变量以便在async中能够修改
    //不用Arc<node>的原因是,Arc用于共享不可变数据，多个线程可以同时访问,但如果有一个线程尝试修改它，就可能会导致竞争条件和不确定的行为
    let node = Node::init(gs_tbk_config);
    let shared_node = Arc::new(TokioMutex::new(node.clone()));

    //设置dec阶段的共享变量
    let shared_dec_phase_one_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeDecPhaseOneBroadcastMsg>::new()));

    //开启节点监听接口
    let node_addr:SocketAddr = node.address.parse()?;
    let listener = TcpListener::bind(node_addr).await?;
    info!("node4 is listening on {}",node.address);

    //向proxy发送消息，代码，启动
    let node_setup_msg_str = serde_json::to_string(&message::common_msg::GSTBKMsg::GSTBKMsgN(message::node::common_msg::GSTBKMsg::SetupMsg(SetupMsg::NodeToProxySetupPhaseP2PMsg(node.setup_phase_one())))).unwrap();
    match p2p(node_setup_msg_str, node.proxy_address).await
    {
        Ok(_) => {}
        Err(e) => 
        {
            error!("node setup msg can not sent Err:{}",e);
        }
    };

    //循环接受消息
    while let Result::Ok(( tcp_stream,_)) = listener.accept().await
    {
        //对共享变量进行克隆
        let node_clone = shared_node.clone();
        
        //dec阶段
        let dec_phase_one_msg_vec_clone = shared_dec_phase_one_msg_vec.clone();

        tokio::spawn(async move
        {
            //闭包里克隆共享变量
            let node = node_clone.clone();

            //dec阶段
            let dec_phase_one_msg_vec = dec_phase_one_msg_vec_clone.clone();
            //接收并拆分出消息
            let framed = Framed::new( tcp_stream,LinesCodec::new());
            let message = match get_message(framed).await
            {
                Ok(v) => v,
                Err(e) => 
                {
                    error!("Failed to get nodemessage: {:?}",e);
                    return ;
                }
            }; 
            match message 
            {
                GSTBKMsg::GSTBKMsgP(gstbk_proxy_msg) => 
                {
                    match gstbk_proxy_msg
                    {
                        message::proxy::common_msg::GSTBKMsg::SetupMsg(setup_msg) => 
                        {
                            match setup_msg 
                            {
                                message::proxy::common_msg::SetupMsg::ProxySetupPhaseBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxySetupPhaseBroadcastMsg");
                                    let mut locked_node = node.lock().await;
                                    let setup_phase_two_msg_str = setup_to_gstbk(SetupMsg::NodeSetupPhaseFinishFlag(locked_node.setup_phase_two(msg)));
                                    match p2p(setup_phase_two_msg_str, (*locked_node.proxy_address).to_string()).await 
                                    {
                                        Ok(_) => {}
                                        Err(e) => 
                                        {
                                            error!("Error: {}, NodeToProxySetupFinishMsg can not sent ",e);
                                            return ;
                                        }
                                    };
                                }
                                message::proxy::common_msg::SetupMsg::ProxySetupPhaseFinishFlag(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxySetupPhaseFinishFlag");
                                    let locked_node = node.lock().await;
                                    locked_node.setup_phase_three();
                                }
                            }
        
                        }
                        message::proxy::common_msg::GSTBKMsg::DecMsg(dec_msg) => 
                        {
                            match dec_msg
                            {
                                message::proxy::common_msg::DecMsg::ProxyDecPhaseOneBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodeKeyGenPhaseThreeP2PMsg");
        
                                    let mut locked_node = node.lock().await;
                                    
                                    info!("Decrypt phase is staring!");

                                    //压入自己的vec
                                    let mut locked_vec = dec_phase_one_msg_vec.lock().await;

                                    //生成并序列化NodeKeyGenPhaseOneBroadcastMsg
                                    info!("Calculate phase one msg!");
                                    let dec_phase_one_msg = locked_node.dec_phase_one(msg.clone());
                                    locked_vec.push(dec_phase_one_msg.clone());
                                    info!("Calculate phase five str!");
                                    let dec_phase_one_msg_str = dec_to_gstbk(DecMsg::NodeDecPhaseOneBroadcastMsg(dec_phase_one_msg));

                                    let mut msg_vec:Vec<String> = Vec::new();
                                    msg_vec.push(dec_phase_one_msg_str);
                                    let node_list = locked_node.node_info_vec.clone().unwrap();

                                    let node_id = locked_node.id.clone().unwrap();

                                    //将消息广播发送出去
                                    for msg in msg_vec
                                    {
                                        match broadcast(msg, node_list.clone(),node_id.clone()).await
                                        {
                                            Ok(_) => {}
                                            Err(e) => 
                                            {
                                                error!("Error: {}, NodeKeyGenPhaseFiveBroadcastMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    info!("Decrypt msg is sended!");
                                    // if *locked_num == locked_node.threashold_param.share_counts as i32 
                                    // {
                                    //     let keygen_phase_five_msg_str = keygen_to_gstbk(KeyGenMsg::NodeToProxyKeyGenPhaseFiveP2PMsg(locked_node.keygen_phase_five()));
                                    //     match p2p(keygen_phase_five_msg_str, (*locked_node.proxy_address).to_string()).await 
                                    //     {
                                    //         Ok(_) => {}
                                    //         Err(e) => 
                                    //         {
                                    //             error!("Error: {}, NodeToProxyKeyGenPhaseFiveP2PMsg can not sent ",e);
                                    //             return ;
                                    //         }
                                    //     };
                                    // }
                                }
                                _ => {} 
                            }
                        } _ => {} 
                    }
                }
                GSTBKMsg::GSTBKMsgN(gstbk_node_msg) => 
                {
                    match gstbk_node_msg
                    {
                        message::node::common_msg::GSTBKMsg::DecMsg(dec_msg) => 
                        {
                            match dec_msg
                            {
                                message::node::common_msg::DecMsg::NodeDecPhaseOneBroadcastMsg(msg) => 
                                {
                                    info!("From id : {} ,Role : {} Get NodeKeyGenPhaseFiveBroadcastMsg ",msg.sender,msg.role);
                                    let mut locked_node = node.lock().await;
                                    let mut locked_vec = dec_phase_one_msg_vec.lock().await;
                                    locked_vec.push(msg);
                                    if locked_vec.len() == locked_node.threashold_param.share_counts as usize  
                                    {
                                        let vec = (*locked_vec).clone();
                                        locked_node.dec_phase_two(&vec);
                                        // {
                                        //     Ok(v) => v,
                                        //     Err(e) => 
                                        //     {
                                        //         error!("Error:{}, can not get NodeToProxyKeyGenPhaseTwoP2PMsg_A ",e);
                                        //         return ;
                                        //     }
                                        // };
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        });
    }
    Ok(())
}



#[tokio::main]
pub async fn main() -> Result<(), anyhow::Error> 
{
    // 初始化 日志记录器
    let log_path = String::from(env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/node/node4/config/config_file/log4rs.yaml";
    log4rs::init_file(log_path, Default::default()).unwrap();
    
    //初始化node
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/node/node4/config/config_file/node_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();

    //将node设置成共享变量以便在async中能够修改
    //不用Arc<node>的原因是,Arc用于共享不可变数据，多个线程可以同时访问,但如果有一个线程尝试修改它，就可能会导致竞争条件和不确定的行为
    let node = Node::init(gs_tbk_config);
    let shared_node = Arc::new(TokioMutex::new(node.clone()));

    //设置keygen阶段的共享变量
    let shared_keygen_phase_one_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeKeyGenPhaseOneBroadcastMsg>::new()));
    let shared_keygen_phase_five_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeKeyGenPhaseFiveBroadcastMsg>::new()));
    let shared_xj_num = Arc::new(TokioMutex::new(0));

    //开启节点监听接口
    let node_addr:SocketAddr = node.address.parse()?;
    let listener = TcpListener::bind(node_addr).await?;
    info!("node4 is listening on {}",node.address);

    //向proxy发送消息，代码，启动
    let node_setup_msg_str = serde_json::to_string(&message::common_msg::GSTBKMsg::GSTBKMsgN(message::node::common_msg::GSTBKMsg::SetupMsg(SetupMsg::NodeToProxySetupPhaseP2PMsg(node.setup_phase_one())))).unwrap();
    match p2p(node_setup_msg_str, node.proxy_address).await
    {
        Ok(_) => {}
        Err(e) => 
        {
            error!("node setup msg can not sent Err:{}",e);
        }
    };

    //循环接受消息
    while let Result::Ok(( tcp_stream,_)) = listener.accept().await
    {
        //对共享变量进行克隆
        let node_clone = shared_node.clone();
        
        //keygen阶段
        let keygen_phase_one_msg_vec_clone = shared_keygen_phase_one_msg_vec.clone();
        let keygen_phase_five_msg_vec_clone = shared_keygen_phase_five_msg_vec.clone();
        let xj_num_clone = shared_xj_num.clone();

        tokio::spawn(async move
            {
            //闭包里克隆共享变量
            let node = node_clone.clone();

            //keygen阶段
            let keygen_phase_one_msg_vec = keygen_phase_one_msg_vec_clone.clone();
            let keygen_phase_five_msg_vec = keygen_phase_five_msg_vec_clone.clone();
            let xj_num = xj_num_clone.clone();
            //接收并拆分出消息
            let framed = Framed::new( tcp_stream,LinesCodec::new());
            let message = match get_message(framed).await
            {
                Ok(v) => v,
                Err(e) => 
                {
                    error!("Failed to get nodemessage: {:?}",e);
                    return ;
                }
            }; 
            match message 
            {
                GSTBKMsg::GSTBKMsgP(gstbk_proxy_msg) => 
                {
                    match gstbk_proxy_msg
                    {
                        message::proxy::common_msg::GSTBKMsg::SetupMsg(setup_msg) => 
                        {
                            match setup_msg 
                            {
                                message::proxy::common_msg::SetupMsg::ProxySetupPhaseBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxySetupPhaseBroadcastMsg");
                                    let mut locked_node = node.lock().await;
                                    let setup_phase_two_msg_str = setup_to_gstbk(SetupMsg::NodeSetupPhaseFinishFlag(locked_node.setup_phase_two(msg)));
                                    match p2p(setup_phase_two_msg_str, (*locked_node.proxy_address).to_string()).await 
                                    {
                                        Ok(_) => {}
                                        Err(e) => 
                                        {
                                            error!("Error: {}, NodeToProxySetupFinishMsg can not sent ",e);
                                            return ;
                                        }
                                    };
                                }
                                message::proxy::common_msg::SetupMsg::ProxySetupPhaseFinishFlag(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxySetupPhaseFinishFlag");
                                    let locked_node = node.lock().await;
                                    locked_node.setup_phase_three();
                                }
                            }
        
                        }
                        message::proxy::common_msg::GSTBKMsg::KeyGenMsg(keygen_msg) => 
                        {
                            match keygen_msg  
                            {
                                message::proxy::common_msg::KeyGenMsg::ProxyKeyGenPhaseStartFlag(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyKeyGenPhaseStartFlag");
                                    //info!("StartFlag is {:?}",msg);
                                }
                                message::proxy::common_msg::KeyGenMsg::ProxyKeyGenPhaseOneBroadcastMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyKeyGenPhaseOneBroadcastMsg");
                                    info!("Keygen phase is staring!");
                                    //生成ABOC
                                    // let tag_A = DKGTag::Gamma_A;
                                    let mut locked_node = node.lock().await;

                                    //压入自己的vec
                                    let mut locked_vec = keygen_phase_one_msg_vec.lock().await;

                                    //生成并序列化NodeKeyGenPhaseOneBroadcastMsg
                                    let keygen_phase_one_msg = locked_node.keygen_phase_one(msg.clone());
                                    locked_vec.push(keygen_phase_one_msg.clone());

                                    let keygen_phase_one_msg_str = keygen_to_gstbk(KeyGenMsg::NodeKeyGenPhaseOneBroadcastMsg(keygen_phase_one_msg));

                                    let mut msg_vec:Vec<String> = Vec::new();
                                    msg_vec.push(keygen_phase_one_msg_str);
                                    let node_list = locked_node.node_info_vec.clone().unwrap();

                                    let node_id = locked_node.id.clone().unwrap();

                                    //将消息广播发送出去
                                    for msg in msg_vec
                                    {
                                        match broadcast(msg, node_list.clone(),node_id.clone()).await
                                        {
                                            Ok(_) => {}
                                            Err(e) => 
                                            {
                                                error!("Error: {}, NodeKeyGenPhaseOneBroadcastMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    info!("Keygen phase one is sended!");
                                   
                                }
                                message::proxy::common_msg::KeyGenMsg::ProxyToNodeKeyGenPhaseThreeP2PMsg(msg) => 
                                {
                                    info!("From id : 0 ,Role : Proxy  Get ProxyToNodeKeyGenPhaseThreeP2PMsg");
                                    let mut locked_num = xj_num.lock().await;
                                    let mut locked_node = node.lock().await;
                                    match locked_node.keygen_phase_four(msg) 
                                    {
                                        Ok(_) => 
                                        {
                                            *locked_num += 1;
                                        }
                                        Err(e) => 
                                        {
                                            error!("can not get xj Err is {}",e);
                                        }
                                    };
                                }
                            }
                        }
                        _ => {} 
                    }
                }
                GSTBKMsg::GSTBKMsgN(gstbk_node_msg) => 
                {
                    match gstbk_node_msg
                    {
                        message::node::common_msg::GSTBKMsg::KeyGenMsg(keygen_msg) => 
                        {
                            match keygen_msg 
                            {
                                message::node::common_msg::KeyGenMsg::NodeKeyGenPhaseOneBroadcastMsg(msg) => 
                                {
                                    info!("From id : {} ,Role : {} Get NodeKeyGenPhaseOneBroadcastMsg ",msg.sender,msg.role);
                                    let mut locked_node = node.lock().await;
                                    let mut locked_vec = keygen_phase_one_msg_vec.lock().await;
                                    locked_vec.push(msg);
                                    if locked_vec.len() == locked_node.threashold_param.share_counts as usize  
                                    {
                                        let vec = (*locked_vec).clone();
                                        let keygen_phase_two_msg = match locked_node.keygen_phase_two(&vec) 
                                        {
                                            Ok(v) => v,
                                            Err(e) => 
                                            {
                                                error!("Error:{}, can not get NodeToProxyKeyGenPhaseTwoP2PMsg_A ",e);
                                                return ;
                                            }
                                        };
                                        let keygen_phase_two_msg_str = serde_json::to_string(&message::common_msg::GSTBKMsg::GSTBKMsgN(message::node::common_msg::GSTBKMsg::KeyGenMsg(message::node::common_msg::KeyGenMsg::NodeToProxyKeyGenPhaseTwoP2PMsg(keygen_phase_two_msg)))).unwrap();
                                        match p2p(keygen_phase_two_msg_str, (*locked_node.proxy_address).to_string()).await 
                                        {
                                            Ok(_) => {}
                                            Err(e) => 
                                            {
                                                error!("Error:{}, NodeToProxyKeyGenPhaseTwoP2PMsg_A can not sent",e);
                                                return ;
                                            }
                                        };
                                    }
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
            }
        });
    }
    Ok(())
}

#[test]
fn test() 
{
    match main() 
    {
        Ok(_) => 
        {
            println!("Ok");
        }
        Err(_) => 
        {
            println!("No");
        } 
    };
}

#[test]
fn test_decrypt() 
{
    match decrypt() 
    {
        Ok(_) => 
        {
            println!("Ok");
        }
        Err(_) => 
        {
            println!("No");
        } 
    };
}