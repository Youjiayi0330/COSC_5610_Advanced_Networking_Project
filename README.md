# COSC_5610_Advanced_Networking_Project
Our project is to test and evaluate [DTP](https://github.com/STAR-Tsinghua/DTP).<br>
You can put `server.rs`,`client.rs`,`server_divide_block.rs` in [DTP/examples](https://github.com/STAR-Tsinghua/DTP/tree/main/examples).
## Files description
### demo.mp4
This is one 6M video. It is used to be test. You can put it in [DTP/examples/root](https://github.com/STAR-Tsinghua/DTP/tree/main/examples/root)
### server.rs
This is the example of server. The server can send large file. It can be used to test SectionIII-B,C,D.<br><br>
When testing `SectionIII-B`, modify alpha in [DTP/src/scheduler/dtp_scheduler.rs](https://github.com/STAR-Tsinghua/DTP/tree/main/src/scheduler).
```
impl Default for DtpScheduler {
    fn default() -> Self {
        DtpScheduler {
            ddl: 0,
            size: 0,
            prio: 999999999, 
            last_block_id: None,
            max_prio: 2,
            alpha: 0.5, // Set alpha value
            beta: 100000.0
        }
    }
}
```
### server_divide_block.rs
This is the example of server. It can be used to test SectionIII-A.<br>
It divides file into 1M blocks and sets priorities to each block.
```
let mut buffer = [0; 1000000]; // Each block has 1000000 bytes

        match large_file_response.file.read(&mut buffer) {
            Ok(0) => {
                ...
            },
            Ok(nbytes) => {
                info!("read {} bytes from the file for stream {}", nbytes, stream_id);
                info!("Number {} block wiht priority {} ", large_file_response.offset/1000000, (large_file_response.offset/1000000)%3);
                if let Err(e) = client.conn.stream_send_full(stream_id, &buffer[..nbytes], false, 200, ((large_file_response.offset/1000000) as u64)%3, 0) {
                    ...
                }
                // Updates the amount of data that has been sent
                large_file_response.offset += nbytes;
                info!(
                    "data has been sent {} bytes",
                    large_file_response.offset
                );
            },
            Err(e) => {
                // Error while reading file, close stream
                ...
            },
        }
```
### client.rs
This is the example of client. It is used to receive file.

## Quick Start
### Server
Run Server.rs
```
cargo run --example server -- --listen 0.0.0.0:4433
```
Check log
```
RUST_LOG=debug ./target/debug/examples/server --listen 0.0.0.0:4433
```
Parameters setting guidline
```
Options:
  --listen <addr>             Listen on the given IP:port [default: 127.0.0.1:4433]
  --cert <file>               TLS certificate path [default: examples/cert.crt]
  --key <file>                TLS certificate key path [default: examples/cert.key]
  --root <dir>                Root directory [default: examples/root]
  --name <str>                Name of the server [default: quic.tech]
  --max-data BYTES            Connection-wide flow control limit [default: 10000000].
  --max-stream-data BYTES     Per-stream flow control limit [default: 1000000].
  --max-streams-bidi STREAMS  Number of allowed concurrent streams [default: 100].
  --max-streams-uni STREAMS   Number of allowed concurrent streams [default: 100].
  --dump-packets PATH         Dump the incoming packets as files in the given directory.
  --early-data                Enables receiving early data.
  --no-retry                  Disable stateless retry.
  -h --help                   Show this screen.
";
```
### Client
Run Client.rs
```
cargo run --example client http://<IP Address>/<FileName> --no-verify
```
Check log
```
RUST_LOG=debug ./target/debug/examples/client http://<IP Address>/<FileName> --no-verify
```
Parameters setting guidline
```
ptions:
  --max-data BYTES         Connection-wide flow control limit [default: 10000000].
  --max-stream-data BYTES  Per-stream flow control limit [default: 1000000].
  --wire-version VERSION   The version number to send to the server [default: babababa].
  --dump-packets PATH      Dump the incoming packets as files in the given directory.
  --no-verify              Don't verify server's certificate.
  -h --help                Show this screen.
";
```
## QUIC
We use [quiche0.2.0](https://github.com/cloudflare/quiche/tree/0.2.0) to compare QUIC with DTP.
