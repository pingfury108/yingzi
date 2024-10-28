use anyhow::Result;
use clap::Parser;
use std::net::Ipv4Addr;
use tokio::net::{TcpListener, TcpStream};

/// benti is the ontology of yingzi
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    target_addr: String,

    #[arg(short, long, default_value_t = 9110)]
    start_port: u16,

    #[arg(short, long, default_value_t = 9120)]
    end_port: u16,

    #[arg(short, long, default_value_t = 9110)]
    listen_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    // TCP 转发器
    let tcp_listener = TcpListener::bind((Ipv4Addr::new(0, 0, 0, 0), args.listen_port)).await?;
    log::info!("listening on 0.0.0:{}", args.listen_port);

    tokio::spawn(async move {
        loop {
            let (mut inbound, _) = tcp_listener.accept().await.unwrap();
            let mut outbound = TcpStream::connect(args.target_addr.clone()).await.unwrap();

            tokio::spawn(async move {
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
            });
        }
    });

    // 保持程序运行
    tokio::signal::ctrl_c().await.unwrap();
    println!("Exiting...");
    Ok(())
}
