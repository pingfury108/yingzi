use anyhow::Result;
use clap::Parser;
use env_logger;
use std::net::Ipv4Addr;
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::{wrappers::TcpListenerStream, StreamExt, StreamMap};

/// yingzi is a tcp/udp data copy tool
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    target_addr: String,

    #[arg(short, long, default_value_t = 9110)]
    start_port: u16,

    #[arg(short, long, default_value_t = 9120)]
    end_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let ports: Vec<u16> = (args.start_port..=args.end_port).collect();
    let mut listeners = StreamMap::new();
    // 添加要监听的端口
    for port in ports {
        let listener = TcpListener::bind((Ipv4Addr::new(0, 0, 0, 0), port)).await?;
        log::info!("Listening on port {}", port);
        listeners.insert(port, TcpListenerStream::new(listener));
    }

    while let Some((_, mut listener)) = listeners.next().await {
        let target_addr = args.target_addr.clone(); // 克隆目标地址，以便在异步块中使用
        tokio::spawn(async move {
            while let Ok(ref mut inbound) = listener {
                log::info!("target_addr: {target_addr}");
                let mut outbound = TcpStream::connect(target_addr.clone()).await.unwrap();

                let (mut ri, mut wi) = inbound.split();
                let (mut ro, mut wo) = outbound.split();

                let client_to_server = tokio::io::copy(&mut ri, &mut wo);
                let server_to_client = tokio::io::copy(&mut ro, &mut wi);

                let (c_s_err, s_c_err) = tokio::join!(client_to_server, server_to_client);
                if let Err(e) = c_s_err {
                    log::error!("client -> server err: {e}");
                };
                if let Err(e) = s_c_err {
                    log::error!("server -> client err: {e}");
                };
            }
        });
    }

    // 保持程序运行
    tokio::signal::ctrl_c().await.unwrap();
    log::info!("Exiting...");
    Ok(())
}
