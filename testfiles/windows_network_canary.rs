use std::io::Write;
use std::net::{TcpStream, UdpSocket};

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [protocol, address, nonce] if protocol == "tcp" => {
            if let Ok(mut stream) = TcpStream::connect(address) {
                let _ = stream.write_all(nonce.as_bytes());
            }
        }
        [protocol, address, nonce] if protocol == "udp" => {
            if let Ok(socket) = UdpSocket::bind("127.0.0.1:0") {
                let _ = socket.send_to(nonce.as_bytes(), address);
            }
        }
        _ => std::process::exit(2),
    }
}
