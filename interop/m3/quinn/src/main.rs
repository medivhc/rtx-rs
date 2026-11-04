use std::net::UdpSocket;
use std::time::Duration;

fn main() {
    println!("rtx-quinn-interop: use tests instead of main binary");
    let _ = UdpSocket::bind("127.0.0.1:0");
    let _ = Duration::from_millis(1);
}
