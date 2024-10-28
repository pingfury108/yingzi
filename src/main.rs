mod tls;

use anyhow::Result;
use clap::Parser;
use std::{net::Ipv4Addr, path::Path};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::{wrappers::TcpListenerStream, StreamExt, StreamMap};

use std::io;
use std::sync::Arc;
use tls::{load_certs, load_keys};
use tokio_rustls::{rustls, TlsAcceptor};

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

    #[arg(short, long)]
    cret: String,

    #[arg(short, long)]
    key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let ports: Vec<u16> = (args.start_port..=args.end_port).collect();

    // tls

    let certs = load_certs(Path::new(args.cret.as_str()))?;
    let key = load_keys(Path::new(args.key.as_str()))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let mut listeners = StreamMap::new();
    // 添加要监听的端口
    for port in ports {
        let listener = TcpListener::bind((Ipv4Addr::new(0, 0, 0, 0), port)).await?;
        log::info!("Listening on port {}", port);
        listeners.insert(port, TcpListenerStream::new(listener));
    }

    while let Some((_, mut listener)) = listeners.next().await {
        let target_addr = args.target_addr.clone(); // 克隆目标地址，以便在异步块中使用
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            while let Ok(ref mut inbound) = listener {
                log::info!("target_addr: {target_addr}");
                let stream = acceptor.accept(inbound).await.expect("");
                let (socket, _) = stream.into_inner();

                let mut outbound = TcpStream::connect(target_addr.clone()).await.unwrap();

                let (mut ri, mut wi) = socket.split();
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
