use std::net::SocketAddr;
use tokio::net::{TcpListener};
use tokio_util::codec::{Framed, LinesCodec};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use std::thread::sleep;
use std::time::Duration;
use std::env;
use log::{error, info, warn};

use proxy::communication::communication::*;
use message::proxy::common_msg::{SetupMsg, KeyGenMsg, DecMsg};
use proxy::proxy::Proxy;
use proxy::config::config::Config;
use message::node::setup_msg::{NodeToProxySetupPhaseP2PMsg,NodeSetupPhaseFinishFlag};
use message::node::keygen_msg::{NodeToProxyKeyGenPhaseTwoP2PMsg};
use message::common_msg::{GSTBKMsg};
// use gs_tbk_scheme::messages::node::key_manage_msg::{NodeToProxyKeyRecoverP2PMsg,NodeToProxyKeyRefreshOneP2PMsg};

#[tokio::main]
pub async fn decrypt () -> Result<(), anyhow::Error> 
{
    // 初始化 日志记录器
    let log_path = String::from(env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/proxy/config/config_file/log4rs.yaml";
    log4rs::init_file(log_path, Default::default()).unwrap();
    
    // 初始化
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/proxy/config/config_file/proxy_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();
    let proxy = Proxy::init(gs_tbk_config);

    // 创建setup阶段的一些共享变量
    let shared_node_setup_p2p_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxySetupPhaseP2PMsg>::new()));
    let setup_msg_num = Arc::new(TokioMutex::new(0));
    let setup_finish_num = Arc::new(TokioMutex::new(0));
    let shared_node_setup_finish_vec = Arc::new(TokioMutex::new(Vec::<NodeSetupPhaseFinishFlag>::new()));
    
    // 开启代理的监听端口
    let proxy_addr:SocketAddr = proxy.address.parse()?;
    let listener = TcpListener::bind(proxy_addr).await?;
    info!("Proxy_node is listening on {}",proxy_addr);
    let shared_proxy = Arc::new(TokioMutex::new(proxy));// 定义共享
    
    // 循环接收消息
    while let Result::Ok(( tcp_stream,_)) = listener.accept().await 
    {
        // 拷贝共享代理结构体
        let proxy_clone = shared_proxy.clone();

        // 拷贝共享变量
        let shared_node_setup_p2p_msg_vec_clone = shared_node_setup_p2p_msg_vec.clone();
        let msg_num_clone = setup_msg_num.clone();                            
        let finish_num_clone = setup_finish_num.clone();
        let node_setup_finish_vec_clone = shared_node_setup_finish_vec.clone();
    
        
        //let open_two_vec_clone = shared_ntp_open_two_vec.clone();
        tokio::spawn(async move
        {
            let proxy = proxy_clone.clone();
            //接收并拆分出消息
            let framed = Framed::new( tcp_stream,LinesCodec::new());
            let message = match get_message(framed).await 
            {
                Ok(v) => v,
                Err(e) => 
                {
                    error!("Failed to get node's message: {:?}",e);
                    return ;
                } 
            };
            //对不同的消息类型做处理
            match message 
            {
                GSTBKMsg::GSTBKMsgN(gstbkn_msg) => 
                {
                    match gstbkn_msg 
                    {
                        message::node::common_msg::GSTBKMsg::SetupMsg(setup_msg) =>  
                        { 
                            match setup_msg 
                            {
                                message::node::common_msg::SetupMsg::NodeToProxySetupPhaseP2PMsg(msg) => 
                                {
                                    info!("From Role : {}, Get NodeToProxySetupPhaseP2PMsg", msg.role);
                                    let node_setup_p2p_msg_vec = shared_node_setup_p2p_msg_vec_clone.clone();
                                    let msg_num = msg_num_clone.clone(); 
                                    let mut locked_proxy = proxy.lock().await;                           
                                    handle_setup_msg(msg,&node_setup_p2p_msg_vec,&msg_num).await;
                                    //判断收到的消息是否达到了n
                                    if *msg_num.lock().await == (locked_proxy.threashold_param.share_counts as i32) 
                                    {
                                        //info!("Setup phase is starting!");
                                        //等待一秒，等所有的节点监听接口都能打开
                                        let duration = Duration::from_secs(1);
                                        sleep(duration); 
                                        //生成proxy_setup_msg 
                                        let msg_vec = (*node_setup_p2p_msg_vec.lock().await).clone();
                                        let setup_msg_str = setup_to_gstbk(SetupMsg::ProxySetupPhaseBroadcastMsg(locked_proxy.setup_phase_one(msg_vec)));
                                        //广播
                                        let node_list = locked_proxy.node_info_vec.clone().unwrap(); 
                                        match broadcast(setup_msg_str, node_list).await{
                                            Ok(_) => 
                                            {
                                                //println!("ProxySetupBroadcastMsg have send");
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error!: {}, ProxySetupBroadcastMsg can not send ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    else 
                                    {
                                        warn!("Insufficient number of messages, and current number is {:?}", msg_num);
                                        return;
                                    }
                                }
                                message::node::common_msg::SetupMsg::NodeSetupPhaseFinishFlag(msg) => 
                                {
                                    info!("From id : {}, Role : {}, Get NodeSetupPhaseFinishFlag",msg.sender,msg.role);
                                    let node_setup_finish_vec = node_setup_finish_vec_clone.clone();
                                    let finish_num = finish_num_clone.clone();
                                    let mut locked_proxy = proxy.lock().await;
                                    handle_setup_tag(msg,&node_setup_finish_vec,&finish_num).await;
                                    //判断是否所有节点都发了
                                    if *finish_num.lock().await == (locked_proxy.threashold_param.share_counts as i32) 
                                    {
                                        let setup_finish_flag_str = setup_to_gstbk(SetupMsg::ProxySetupPhaseFinishFlag(locked_proxy.setup_phase_two((*node_setup_finish_vec.lock().await).clone())));
                                        //广播
                                        let node_list = locked_proxy.node_info_vec.clone().unwrap(); 
                                        match broadcast(setup_finish_flag_str, node_list).await
                                        {
                                            Ok(_) => {
                                                //println!("ProxySetupFinishMsg have send");
                                            }
                                            Err(e) => {
                                                error!("Error: {}, ProxySetupFinishMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    else 
                                    {
                                        warn!("Insufficient number of messages, and current number is {:?}", finish_num);
                                        return;
                                    }

                                    //生成Dec的消息
                                    let (dec_start_flag,dec_phase_one_msg) = locked_proxy.dec_phase_one();
                                    //处理发送proxy的Phaseone DecStartFlag
                                    let dec_start_flag_str = dec_to_gstbk(DecMsg::ProxyDecPhaseStartFlag(dec_start_flag));
                                    //广播
                                    let node_list = locked_proxy.node_info_vec.clone().unwrap(); 
                                    match broadcast(dec_start_flag_str, node_list.clone()).await
                                    {
                                        Ok(_) => 
                                        {
                                            //println!("ProxySetupFinishMsg have send");
                                        }
                                        Err(e) => 
                                        {
                                            error!("KeygenStartFlag can not sent Error: {}",e);
                                            return ;
                                        }
                                    };
                                    //处理发送proxy的Phase_one ProxyKeyGenPhaseOneBroadcastMsg
                                    let dec_phase_one_msg_str = dec_to_gstbk(DecMsg::ProxyDecPhaseOneBroadcastMsg(dec_phase_one_msg));
                                    //广播
                                    match broadcast(dec_phase_one_msg_str, node_list.clone()).await
                                    {
                                        Ok(_) => 
                                        {
                                            //println!("ProxySetupFinishMsg have send");
                                        }
                                        Err(e) => 
                                        {
                                            error!("KeygenPhaseOneMsg can not sent Error: {}",e);
                                            return ;
                                        }
                                    };
                                }
                                
                            }
                        }
                        _ => {}  
                    }
                }
                _ => {}
            }
        });
    }
    Ok(())
}


#[tokio::main]
pub async fn main () -> Result<(), anyhow::Error> 
{
    // 初始化 日志记录器
    let log_path = String::from(env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/proxy/config/config_file/log4rs.yaml";
    log4rs::init_file(log_path, Default::default()).unwrap();
    
    // 初始化
    let gs_tbk_config_path  = String::from(std::env::current_dir().unwrap().as_path().to_str().unwrap())+"/src/proxy/config/config_file/proxy_config.json";
    let gs_tbk_config:Config = serde_json::from_str(&Config::load_config(&gs_tbk_config_path)).unwrap();
    let proxy = Proxy::init(gs_tbk_config);

    // 创建setup阶段的一些共享变量
    let shared_node_setup_p2p_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxySetupPhaseP2PMsg>::new()));
    let setup_msg_num = Arc::new(TokioMutex::new(0));
    let setup_finish_num = Arc::new(TokioMutex::new(0));
    let shared_node_setup_finish_vec = Arc::new(TokioMutex::new(Vec::<NodeSetupPhaseFinishFlag>::new()));
    
    // 创建KeyGen阶段的共享变量
    let shared_keygen_phase_two_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxyKeyGenPhaseTwoP2PMsg>::new()));
    // let shared_keygen_phase_five_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxyKeyGenPhaseFiveP2PMsg>::new()));
    
    // // 创建KeyManage阶段的共享变量
    // let shared_key_recover_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxyKeyRecoverP2PMsg>::new()));
    // let shared_key_refresh_msg_vec = Arc::new(TokioMutex::new(Vec::<NodeToProxyKeyRefreshOneP2PMsg>::new()));

    
    // 开启代理的监听端口
    let proxy_addr:SocketAddr = proxy.address.parse()?;
    let listener = TcpListener::bind(proxy_addr).await?;
    info!("Proxy_node is listening on {}",proxy_addr);
    let shared_proxy = Arc::new(TokioMutex::new(proxy));// 定义共享
    
    // 循环接收消息
    while let Result::Ok(( tcp_stream,_)) = listener.accept().await 
    {
        // 拷贝共享代理结构体
        let proxy_clone = shared_proxy.clone();

        // 拷贝共享变量
        let shared_node_setup_p2p_msg_vec_clone = shared_node_setup_p2p_msg_vec.clone();
        let msg_num_clone = setup_msg_num.clone();                            
        let finish_num_clone = setup_finish_num.clone();
        let node_setup_finish_vec_clone = shared_node_setup_finish_vec.clone();
        
        //keygen阶段克隆
        let keygen_phase_two_msg_vec_clone = shared_keygen_phase_two_msg_vec.clone();
        // let keygen_phase_five_msg_vec_clone = shared_keygen_phase_five_msg_vec.clone();

        // //Key recover
        // let key_recover_msg_vec_clone = shared_key_recover_msg_vec.clone();
        // let key_refresh_msg_vec_clone = shared_key_refresh_msg_vec.clone();
        
        //let open_two_vec_clone = shared_ntp_open_two_vec.clone();
        tokio::spawn(async move
        {
            let proxy = proxy_clone.clone();
            //接收并拆分出消息
            let framed = Framed::new( tcp_stream,LinesCodec::new());
            let message = match get_message(framed).await 
            {
                Ok(v) => v,
                Err(e) => 
                {
                    error!("Failed to get node's message: {:?}",e);
                    return ;
                } 
            };
            //对不同的消息类型做处理
            match message 
            {
                GSTBKMsg::GSTBKMsgN(gstbkn_msg) => 
                {
                    match gstbkn_msg 
                    {
                        message::node::common_msg::GSTBKMsg::SetupMsg(setup_msg) =>  
                        { 
                            match setup_msg 
                            {
                                message::node::common_msg::SetupMsg::NodeToProxySetupPhaseP2PMsg(msg) => 
                                {
                                    info!("From Role : {}, Get NodeToProxySetupPhaseP2PMsg", msg.role);
                                    let node_setup_p2p_msg_vec = shared_node_setup_p2p_msg_vec_clone.clone();
                                    let msg_num = msg_num_clone.clone(); 
                                    let mut locked_proxy = proxy.lock().await;                           
                                    handle_setup_msg(msg,&node_setup_p2p_msg_vec,&msg_num).await;
                                    //判断收到的消息是否达到了n
                                    if *msg_num.lock().await == (locked_proxy.threashold_param.share_counts as i32) 
                                    {
                                        //info!("Setup phase is starting!");
                                        //等待一秒，等所有的节点监听接口都能打开
                                        let duration = Duration::from_secs(1);
                                        sleep(duration); 
                                        //生成proxy_setup_msg 
                                        let msg_vec = (*node_setup_p2p_msg_vec.lock().await).clone();
                                        let setup_msg_str = setup_to_gstbk(SetupMsg::ProxySetupPhaseBroadcastMsg(locked_proxy.setup_phase_one(msg_vec)));
                                        //广播
                                        let node_list = locked_proxy.node_info_vec.clone().unwrap(); 
                                        match broadcast(setup_msg_str, node_list).await{
                                            Ok(_) => 
                                            {
                                                //println!("ProxySetupBroadcastMsg have send");
                                            }
                                            Err(e) => 
                                            {
                                                error!("Error!: {}, ProxySetupBroadcastMsg can not send ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    else 
                                    {
                                        warn!("Insufficient number of messages, and current number is {:?}", msg_num);
                                        return;
                                    }
                                }
                                message::node::common_msg::SetupMsg::NodeSetupPhaseFinishFlag(msg) => 
                                {
                                    info!("From id : {}, Role : {}, Get NodeSetupPhaseFinishFlag",msg.sender,msg.role);
                                    let node_setup_finish_vec = node_setup_finish_vec_clone.clone();
                                    let finish_num = finish_num_clone.clone();
                                    let mut locked_proxy = proxy.lock().await;
                                    handle_setup_tag(msg,&node_setup_finish_vec,&finish_num).await;
                                    //判断是否所有节点都发了
                                    if *finish_num.lock().await == (locked_proxy.threashold_param.share_counts as i32) 
                                    {
                                        let setup_finish_flag_str = setup_to_gstbk(SetupMsg::ProxySetupPhaseFinishFlag(locked_proxy.setup_phase_two((*node_setup_finish_vec.lock().await).clone())));
                                        //广播
                                        let node_list = locked_proxy.node_info_vec.clone().unwrap(); 
                                        match broadcast(setup_finish_flag_str, node_list).await
                                        {
                                            Ok(_) => {
                                                //println!("ProxySetupFinishMsg have send");
                                            }
                                            Err(e) => {
                                                error!("Error: {}, ProxySetupFinishMsg can not sent ",e);
                                                return ;
                                            }
                                        };
                                    }
                                    else 
                                    {
                                        warn!("Insufficient number of messages, and current number is {:?}", finish_num);
                                        return;
                                    }

                                    //生成第二轮KeyGen的消息
                                    let (keygen_start_flag,keygen_phase_one_msg) = locked_proxy.keygen_phase_one();
                                    //处理发送proxy的Phaseone KeyGenStartFlag
                                    let keygen_start_flag_str = keygen_to_gstbk(KeyGenMsg::ProxyKeyGenPhaseStartFlag(keygen_start_flag));
                                    //广播
                                    let node_list = locked_proxy.node_info_vec.clone().unwrap(); 
                                    match broadcast(keygen_start_flag_str, node_list.clone()).await
                                    {
                                        Ok(_) => 
                                        {
                                            //println!("ProxySetupFinishMsg have send");
                                        }
                                        Err(e) => 
                                        {
                                            error!("KeygenStartFlag can not sent Error: {}",e);
                                            return ;
                                        }
                                    };
                                    //处理发送proxy的Phase_one ProxyKeyGenPhaseOneBroadcastMsg
                                    let keygen_phase_one_msg_str = keygen_to_gstbk(KeyGenMsg::ProxyKeyGenPhaseOneBroadcastMsg(keygen_phase_one_msg));
                                    //广播
                                    match broadcast(keygen_phase_one_msg_str, node_list.clone()).await
                                    {
                                        Ok(_) => 
                                        {
                                            //println!("ProxySetupFinishMsg have send");
                                        }
                                        Err(e) => 
                                        {
                                            error!("KeygenPhaseOneMsg can not sent Error: {}",e);
                                            return ;
                                        }
                                    };
                                }
                                
                            }
                        }
                        message::node::common_msg::GSTBKMsg::KeyGenMsg(keygen_msg) => 
                        {
                            match keygen_msg {
                                message::node::common_msg::KeyGenMsg::NodeToProxyKeyGenPhaseTwoP2PMsg(msg) => 
                                {
                                    info!("From id : {}, Role : {}, Get NodeSetupPhaseFinishFlag",msg.sender,msg.role);
                                    let locked_proxy = proxy.lock().await;
                                    let keygen_phase_two_msg_vec = keygen_phase_two_msg_vec_clone.clone();
                                    let mut locked_vec = keygen_phase_two_msg_vec.lock().await;
                                    locked_vec.push(msg);
                                    if locked_vec.len() == locked_proxy.threashold_param.share_counts as usize 
                                    {
                                        let vec = (*locked_vec).clone();
                                        let node_list = locked_proxy.node_info_vec.clone().unwrap();
                                        let keygen_phase_three_msg_map =  locked_proxy.keygen_phase_three(vec).unwrap();
                                        for (node_id , keygen_phase_three_msg) in keygen_phase_three_msg_map
                                        {
                                            let keygen_phase_three_msg_str = keygen_to_gstbk(KeyGenMsg::ProxyToNodeKeyGenPhaseThreeP2PMsg(keygen_phase_three_msg));
                                            match p2p(keygen_phase_three_msg_str, node_id, node_list.clone()).await 
                                            {
                                                Ok(_) => 
                                                {
                                                    //println!("ProxyToNodeKeyGenPhaseThreeP2PMsg_a have send");
                                                }
                                                Err(e) => 
                                                {
                                                    error!("Error: {}, ProxyToNodeKeyGenPhaseThreeP2PMsg_A can not sent ",e);
                                                    return ;
                                                }
                                            }; 
                                        }
                                    }
                                }
                                // message::node::common_msg::KeyGenMsg::NodeToProxyKeyGenPhaseFiveP2PMsg(msg) => 
                                // {
                                //     info!("From id : {}, Role : {},  Get NodeToProxyKeyGenPhaseFiveP2PMsg",msg.sender,msg.role);
                                //     let mut locked_proxy = proxy.lock().await;
                                //     let keygen_five_vec = keygen_phase_five_msg_vec_clone.clone();
                                //     let mut locked_keygen_phase_msg_five_vec = keygen_five_vec.lock().await;
                                //     locked_keygen_phase_msg_five_vec.push(msg);
                                //     if locked_keygen_phase_msg_five_vec.len() == locked_proxy.threashold_param.share_counts as usize 
                                //     {
                                //         let keygen_phase_five_msg_str = keygen_to_gstbk(KeyGenMsg::ProxyToNodesKeyGenPhasefiveBroadcastMsg(locked_proxy.keygen_phase_five((*locked_keygen_phase_msg_five_vec).clone()).unwrap()));
                                //         let node_list = locked_proxy.node_info_vec.clone().unwrap(); 
                                //         match broadcast(keygen_phase_five_msg_str, node_list.clone()).await
                                //         {
                                //             Ok(_) => 
                                //             {
                                //                 //println!("ProxyToNodesKeyGenPhasefiveBroadcastMsg have send");
                                //             }
                                //             Err(e) => 
                                //             {
                                //                 error!("Error: {},ProxyToNodesKeyGenPhasefiveBroadcastMsg can not sent ",e);
                                //                 return ;
                                //             }
                                //         };
                                //     }
                                // }
                                _ => 
                                {

                                }  
                            }
                        }
                        // gs_tbk_scheme::messages::node::common_msg::GSTBKMsg::KeyManageMsg(key_manage_msg)=>
                        // {
                        //     match key_manage_msg
                        //     {
                        //         gs_tbk_scheme::messages::node::common_msg::KeyManageMsg::NodeToProxyKeyRecoverP2PMsg(msg) =>
                        //         {
                        //             info!("From id : {} Role : Node , Get NodeToProxyKeyRecoverP2PMsg",msg.sender);
                        //             let locked_proxy = proxy.lock().await; 
                        //             let key_recover_msg_vec = key_recover_msg_vec_clone.clone();
                        //             let mut locked_recover_vec = key_recover_msg_vec.lock().await;
                        //             locked_recover_vec.push(msg);

                        //             if locked_recover_vec.len() == locked_proxy.threashold_param.share_counts as usize 
                        //             {
                        //                 let recover_vec = (*locked_recover_vec).clone();
                        //                 locked_proxy.key_recover_phase(recover_vec);
                        //             }
                                    
                        //         }
                        //         gs_tbk_scheme::messages::node::common_msg::KeyManageMsg::NodeToProxyKeyRefreshOneP2PMsg(msg) =>
                        //         {
                        //             info!("From id : {} Role : Node , Get NodeToProxyKeyRefreshOneP2PMsg",msg.sender);
                        //             let locked_proxy = proxy.lock().await; 
                        //             let key_refresh_msg_vec = key_refresh_msg_vec_clone.clone();
                        //             let mut locked_refresh_vec = key_refresh_msg_vec.lock().await;
                        //             locked_refresh_vec.push(msg);

                        //             if locked_refresh_vec.len() == locked_proxy.threashold_param.share_counts as usize
                        //             {
                        //                 let refresh_vec = (*locked_refresh_vec).clone();
                        //                 let node_list = locked_proxy.node_info_vec.clone().unwrap();
                        //                 let key_refresh_phase_two_msg_map = match locked_proxy.key_refresh_phase_two(refresh_vec)
                        //                 {
                        //                     Ok(key_refresh_phase_two_msg_map) => key_refresh_phase_two_msg_map,
                        //                     Err(err) => 
                        //                     {
                        //                         error!("Error: {}, Key refresh phase two error",err);
                        //                         return ;
                        //                     }
                        //                 };

                        //                 for (node_id, key_refresh_phase_two_msg) in key_refresh_phase_two_msg_map
                        //                 {
                        //                     let key_refresh_phase_two_msg_str = key_manage_to_gstbk(KeyManageMsg::ProxyToNodeKeyRefreshPhaseTwoP2PMsg(key_refresh_phase_two_msg));
                        //                     match p2p(key_refresh_phase_two_msg_str, node_id, node_list.clone()).await 
                        //                     {
                        //                         Ok(_) => 
                        //                         {
                        //                             //println!("ProxyToNodeKeyRefreshPhaseTwoP2PMsg have send");
                        //                         }
                        //                         Err(e) => 
                        //                         {
                        //                             error!("Error: {}, ProxyToNodeKeyRefreshPhaseTwoP2PMsg can not sent",e);
                        //                             return ;
                        //                         }
                        //                     }; 
                        //                 }
                        //             }
                        //         }
                        //     }
                        // }
                        _ => {}  
                    }
                }
                _ => 
                {

                }
                
            }
        });
    }
    Ok(())
}

//test
#[test]
fn test() 
{
   match main() 
   {
    Ok(_) =>
    {
        info!("Ok");
    }
    Err(_) => 
    {
        error!("No");
    }
   };
}

//test
#[test]
fn decrypt_test() 
{
   match decrypt() 
   {
    Ok(_) =>
    {
        info!("Ok");
    }
    Err(_) => 
    {
        error!("No");
    }
   };
}
