#![cfg(feature = "pop-http")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use jam_messenger::pop::PoPRegistry;

#[test]
fn real_http_client_verifier_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).unwrap();

        let body = r#"{"accepted":true,"provider":"worldid-http-real","nullifier":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    });

    let endpoint = format!("http://{}", addr);
    let registry = PoPRegistry::with_real_http_provider("worldid-http-real", &endpoint);

    let account = [1u8; 32];
    let nullifier = [9u8; 32];
    let res = registry.verify(
        "worldid-http-real",
        &account,
        &nullifier,
        &[1, 2, 3],
        10,
        100,
    );

    handle.join().unwrap();
    assert!(res.is_ok());
}
