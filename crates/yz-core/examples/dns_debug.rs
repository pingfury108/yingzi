use std::time::Duration;
use yz_core::dns::{resolve_upstream, Message, Upstream};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    for up in ["udp://223.5.5.5", "tcp://223.5.5.5", "tls://1.1.1.1:853#cloudflare-dns.com"] {
        let u = Upstream::parse(up)?;
        let q = Message::query("www.baidu.com", 1);
        println!("--- {up} 查询 {} 字节 ---", q.len());
        match tokio::time::timeout(Duration::from_secs(8), resolve_upstream(&u, &q, None, None)).await {
            Ok(Ok(resp)) => {
                println!("  应答 {} 字节", resp.len());
                match Message::parse(&resp) {
                    Ok(m) => println!("  answers: {:?}", m.answers.iter().map(|a| a.3.to_string()).collect::<Vec<_>>()),
                    Err(e) => println!("  解析失败: {e:#}"),
                }
            }
            Ok(Err(e)) => println!("  失败: {e:#}"),
            Err(_) => println!("  超时"),
        }
    }
    Ok(())
}
