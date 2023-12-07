#[macro_use]
extern crate log;

use std::net;

use std::io::prelude::*;

use std::collections::HashMap;

use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

const SOME_MAX_SIZE: u64 = 5 * 1024 * 1024;

const USAGE: &str = "Usage:
  server [options]
  server -h | --help

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

struct PartialResponse {
    body: Vec<u8>,

    written: usize,
}

//跟踪大文件传输
struct LargeFileResponse {
    file: std::fs::File,
    offset: usize,
}

struct Client {
    conn: std::pin::Pin<Box<quiche::Connection>>,

    partial_responses: HashMap<u64, PartialResponse>,

    stream_id: u64,

    large_file_responses: HashMap<u64, LargeFileResponse>
}


type ClientMap = HashMap<Vec<u8>, (net::SocketAddr, Client)>;

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    let args = docopt::Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

    let max_data = args.get_str("--max-data");
    let max_data = u64::from_str_radix(max_data, 10).unwrap();

    let max_stream_data = args.get_str("--max-stream-data");
    let max_stream_data = u64::from_str_radix(max_stream_data, 10).unwrap();

    let max_streams_bidi = args.get_str("--max-streams-bidi");
    let max_streams_bidi = u64::from_str_radix(max_streams_bidi, 10).unwrap();

    let max_streams_uni = args.get_str("--max-streams-uni");
    let max_streams_uni = u64::from_str_radix(max_streams_uni, 10).unwrap();

    let dump_path = if args.get_str("--dump-packets") != "" {
        Some(args.get_str("--dump-packets"))
    } else {
        None
    };

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let socket = net::UdpSocket::bind(args.get_str("--listen")).unwrap();

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )
    .unwrap();

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config
        .load_cert_chain_from_pem_file(args.get_str("--cert"))
        .unwrap();
    config
        .load_priv_key_from_pem_file(args.get_str("--key"))
        .unwrap();

    config
        .set_application_protos(b"\x05hq-24\x05hq-23\x08http/0.9")
        .unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_packet_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(max_data);
    config.set_initial_max_stream_data_bidi_local(max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(max_stream_data);
    config.set_initial_max_stream_data_uni(max_stream_data);
    config.set_initial_max_streams_bidi(max_streams_bidi);
    config.set_initial_max_streams_uni(max_streams_uni);
    config.set_disable_active_migration(true);

    if args.get_bool("--early-data") {
        config.enable_early_data();
    }

    if std::env::var_os("SSLKEYLOGFILE").is_some() {
        config.log_keys();
    }

    let mut clients = ClientMap::new();

    let mut pkt_count = 0;

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout =
            clients.values().filter_map(|(_, c)| c.conn.timeout()).min();

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("timed out");

                clients.values_mut().for_each(|(_, c)| c.conn.on_timeout());

                break 'read;
            }

            let (len, src) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            debug!("got {} bytes", len);

            let pkt_buf = &mut buf[..len];

            if let Some(target_path) = dump_path {
                let path = format!("{}/{}.pkt", target_path, pkt_count);

                if let Ok(f) = std::fs::File::create(&path) {
                    let mut f = std::io::BufWriter::new(f);
                    f.write_all(pkt_buf).ok();
                }
            }

            pkt_count += 1;

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue;
                },
            };

            trace!("got packet {:?}", hdr);

            if hdr.ty == quiche::Type::VersionNegotiation {
                error!("Version negotiation invalid on the server");
                continue;
            }

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let (_, client) = if !clients.contains_key(&hdr.dcid) {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, &src) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue;
                }

                // Generate a random source connection ID for the connection.
                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                SystemRandom::new().fill(&mut scid[..]).unwrap();

                let mut odcid = None;

                if !args.get_bool("--no-retry") {
                    // Token is always present in Initial packets.
                    let token = hdr.token.as_ref().unwrap();

                    // Do stateless retry if the client didn't send a token.
                    if token.is_empty() {
                        warn!("Doing stateless retry");

                        let new_token = mint_token(&hdr, &src);

                        let len = quiche::retry(
                            &hdr.scid, &hdr.dcid, &scid, &new_token, &mut out,
                        )
                        .unwrap();

                        let out = &out[..len];

                        if let Err(e) = socket.send_to(out, &src) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                debug!("send() would block");
                                break;
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        continue;
                    }

                    odcid = validate_token(&src, token);

                    // The token was not valid, meaning the retry failed, so
                    // drop the packet.
                    if odcid == None {
                        error!("Invalid address validation token");
                        continue;
                    }

                    if scid.len() != hdr.dcid.len() {
                        error!("Invalid destination connection ID");
                        continue;
                    }

                    // Reuse the source connection ID we sent in the Retry
                    // packet, instead of changing it again.
                    scid.copy_from_slice(&hdr.dcid);
                }

                debug!(
                    "New connection: dcid={} scid={}",
                    hex_dump(&hdr.dcid),
                    hex_dump(&scid)
                );

                let conn = quiche::accept(&scid, odcid, &mut config).unwrap();

                let client = Client {
                    conn,
                    partial_responses: HashMap::new(),
                    stream_id: 1u64,
                    large_file_responses: HashMap::new()
                };

                clients.insert(scid.to_vec(), (src, client));

                clients.get_mut(&scid[..]).unwrap()
            } else {
                clients.get_mut(&hdr.dcid).unwrap()
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("{} done reading", client.conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    break 'read;
                },
            };

            debug!("{} processed {} bytes", client.conn.trace_id(), read);

            if client.conn.is_in_early_data() || client.conn.is_established() {
                // Handle writable streams.
                for stream_id in client.conn.writable() {
                    handle_writable(client, stream_id);
                }

                // Process all readable streams.
                for s in client.conn.readable() {
                    while let Ok((read, fin)) =
                        client.conn.stream_recv(s, &mut buf)
                    {
                        debug!(
                            "{} received {} bytes",
                            client.conn.trace_id(),
                            read
                        );

                        let stream_buf = &buf[..read];

                        debug!(
                            "{} stream {} has {} bytes (fin? {})",
                            client.conn.trace_id(),
                            s,
                            stream_buf.len(),
                            fin
                        );

                        handle_stream(
                            client,
                            s,
                            stream_buf,
                            args.get_str("--root"),
                        );
                    }
                }
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        for (peer, client) in clients.values_mut() {
            let mut total_written_bytes: usize = 0; // 声明一个变量来存储累计写入的字节数

            loop {
                let write = match client.conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("{} done writing", client.conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", client.conn.trace_id(), e);

                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                // TODO: coalesce packets.
                if let Err(e) = socket.send_to(&out[..write], &peer) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("send() would block");
                        break;
                    }

                    panic!("send() failed: {:?}", e);
                }

                total_written_bytes += write;

                info!("{} 已写入 {} bytes", client.conn.trace_id(), total_written_bytes);
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, (_, ref mut c)| {
            debug!("Collecting garbage");

            if c.conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    c.conn.trace_id(),
                    c.conn.stats()
                );
            }

            !c.conn.is_closed()
        });
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<&'a [u8]> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    let token = &token[addr.len()..];

    Some(&token[..])
}

/// Handles incoming HTTP/0.9 requests.
fn handle_stream(client: &mut Client, stream_id: u64, buf: &[u8], root: &str) {
    info!(
        "handle_stream函数被调用"
    );
    let conn = &mut client.conn;

    if buf.len() > 4 && &buf[..4] == b"GET " {
        let uri = &buf[4..buf.len()];
        let uri = String::from_utf8(uri.to_vec()).unwrap();
        let uri = String::from(uri.lines().next().unwrap());
        let uri = std::path::Path::new(&uri);
        let mut path = std::path::PathBuf::from(root);

        for c in uri.components() {
            if let std::path::Component::Normal(v) = c {
                path.push(v)
            }
        }

        info!(
            "{} got GET request for {:?} on stream {}",
            conn.trace_id(),
            path,
            stream_id
        );

        // 获取文件的元数据以检查其大小。
        let metadata = std::fs::metadata(&path).unwrap();
        // 检查文件是否大于某个预设的大小阈值。
        // 如果是大文件，我们将采取不同的读取和发送策略。
        if metadata.len() > SOME_MAX_SIZE { // SOME_MAX_SIZE 是你设定的大小阈值
            info!("开始读取大文件");
            // 打开文件准备读取。
            let file = std::fs::File::open(&path).unwrap();

            // 创建一个LargeFileResponse实例，用于跟踪文件的读取状态。
            let large_file_response = LargeFileResponse { file, offset: 0 };

            // 将这个LargeFileResponse实例与当前的流ID相关联，存储在client中。
            client.large_file_responses.insert(stream_id, large_file_response);
        } else {
            // 如果文件不是大文件，按原来的方式处理（即一次性读取整个文件内容）。
            let body = std::fs::read(path.as_path())
            .unwrap_or_else(|_| b"Not Found!\r\n".to_vec());

            info!(
                "{} sending response of size {} on stream {}",
                conn.trace_id(),
                body.len(),
                stream_id
            );

            let written =
                match conn.stream_send_full(stream_id, &body, false, 100, 0, 0) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => 0,

                    Err(e) => {
                        error!("{} stream send failed {:?}", conn.trace_id(), e);
                        return;
                    },
                };

            if written < body.len() {
                let response = PartialResponse { body, written };
                client.partial_responses.insert(stream_id, response);
            }
        }       
    }
}

/// Handles newly writable streams.
fn handle_writable(client: &mut Client, stream_id: u64) {
    info!(
        "handle_writable函数被调用"
    );
    let conn = &mut client.conn;

    debug!("{} stream {} is writable", conn.trace_id(), stream_id);

    // 首先，处理部分响应（如果存在）。
    if let Some(resp) = client.partial_responses.get_mut(&stream_id) {
        info!(
            "开始处理部分响应_writable "
        );
        let body = &resp.body[resp.written..];

        let written = match conn.stream_send_full(stream_id, &body, false, 100, 0, 0) {
            Ok(v) => v,
            Err(quiche::Error::Done) => 0,
            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            },
        };

        resp.written += written;

        // 如果已发送全部数据，则从映射中移除该响应。
        if resp.written == resp.body.len() {
            client.partial_responses.remove(&stream_id);
        }
    }

    // 接下来，处理大文件响应（如果存在）。
    if let Some(large_file_response) = client.large_file_responses.get_mut(&stream_id) {
        info!(
            "开始处理大文件响应_writable {}"
        );
        let mut buffer = [0; 65535]; // 使用固定大小的缓冲区。

        match large_file_response.file.read(&mut buffer) {
            Ok(0) => {
                // 文件读取完毕，可以从映射中移除。
                client.large_file_responses.remove(&stream_id);
            },
            Ok(nbytes) => {
                info!("读取 {} bytes from the 大文件 for stream {}", nbytes, stream_id);
                if let Err(e) = client.conn.stream_send_full(stream_id, &buffer[..nbytes], false, 200, 1, 0) {
                    error!("发送数据块到流失败 {}: {:?}", stream_id, e);
                    // 发生错误时关闭流
                    if let Err(e) = client.conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0) {
                        error!("关闭流失败 {}: {:?}", stream_id, e);
                    }
                    return;
                }
                // 更新已发送的数据量。
                large_file_response.offset += nbytes;
                info!(
                    "已发送数据量 {}",
                    large_file_response.offset
                );
            },
            Err(e) => {
                // 读取文件时出错，关闭流。
                error!("读取文件失败 {}: {:?}", stream_id, e);
                if let Err(e) = client.conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0) {
                    error!("关闭文件流失败 {}: {:?}", stream_id, e);
                }
            },
        }
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}
