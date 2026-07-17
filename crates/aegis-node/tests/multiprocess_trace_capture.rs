//! Multi-process trace capture via spawned `aegis-node` / `aegis-client` binaries.
//!
//! More reliable than Python `cargo run` orchestration on Windows: builds once,
//! uses OS-assigned ports, readiness probes, and `--raw` client sends.

use std::fs::{self, File};
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aegis_crypto::fragment::SPHINX_FRAGMENT_COUNT;

const PATH_LEN: usize = 4;
const N_SENDS: usize = 48;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn trace_path() -> PathBuf {
    workspace_root()
        .join("sim")
        .join("data")
        .join("real_multiprocess_trace.csv")
}

fn config_dir() -> PathBuf {
    workspace_root()
        .join("sim")
        .join("data")
        .join("testnet_configs")
}

fn debug_bin(name: &str) -> PathBuf {
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    workspace_root()
        .join("crates")
        .join("target")
        .join("debug")
        .join(exe)
}

fn hex32(b0: u8, b1: u8) -> String {
    let mut buf = [0u8; 32];
    buf[0] = b0;
    buf[1] = b1;
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn link_key(tag: u8) -> String {
    hex32(tag, 0)
}

fn allocate_ports(count: usize) -> Vec<u16> {
    (0..count)
        .map(|_| {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
            let port = listener.local_addr().expect("local_addr").port();
            drop(listener);
            port
        })
        .collect()
}

fn wait_listen(addr: SocketAddr, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for {addr}");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn write_configs(ports: &[u16]) -> PathBuf {
    let dir = config_dir();
    fs::create_dir_all(&dir).expect("config dir");
    let ids: Vec<String> = (0..PATH_LEN).map(|i| hex32((i + 1) as u8, 0)).collect();

    for i in 0..PATH_LEN {
        let mut peers = String::new();
        if i > 0 {
            peers.push_str(&format!(
                "\n[[peers]]\nid = \"{}\"\naddr = \"127.0.0.1:{}\"\nlink_key = \"{}\"\n",
                ids[i - 1],
                ports[i - 1],
                link_key(i as u8),
            ));
        }
        if i + 1 < PATH_LEN {
            peers.push_str(&format!(
                "\n[[peers]]\nid = \"{}\"\naddr = \"127.0.0.1:{}\"\nlink_key = \"{}\"\n",
                ids[i + 1],
                ports[i + 1],
                link_key((i + 1) as u8),
            ));
        }

        let ingress = if i == 0 {
            format!(
                "\n[ingress]\nlink_key = \"{}\"\n",
                link_key(0xC0)
            )
        } else {
            String::new()
        };

        let toml = format!(
            "relay_id = \"{}\"\nlisten = \"127.0.0.1:{}\"\nmu = 80.0\n\n[kem]\nx25519_seed = \"{}\"\nmlkem_d = \"{}\"\nmlkem_z = \"{}\"\n{ingress}{peers}",
            ids[i],
            ports[i],
            hex32(0x10 + i as u8, 0x20 + i as u8),
            hex32(0x30 + i as u8, 0x40 + i as u8),
            hex32(0x50 + i as u8, 0x60 + i as u8),
        );
        fs::write(dir.join(format!("node{i}.toml")), toml).expect("node config");
    }

    let mut hops = String::new();
    for i in 0..PATH_LEN {
        hops.push_str(&format!(
            "\n[[hops]]\nid = \"{}\"\nkem_x25519_seed = \"{}\"\nkem_mlkem_d = \"{}\"\nkem_mlkem_z = \"{}\"\n",
            ids[i],
            hex32(0x10 + i as u8, 0x20 + i as u8),
            hex32(0x30 + i as u8, 0x40 + i as u8),
            hex32(0x50 + i as u8, 0x60 + i as u8),
        ));
    }

    let client = format!(
        "first_hop_addr = \"127.0.0.1:{}\"\ningress_link_key = \"{}\"\npayload = \"mp-trace\"\n{hops}",
        ports[0],
        link_key(0xC0),
    );
    let client_path = dir.join("client.toml");
    fs::write(&client_path, client).expect("client config");
    client_path
}

fn bursty_gaps_ms(rng: &mut rand_core::OsRng, n: usize) -> Vec<u64> {
    use rand_core::RngCore;
    let mut gaps = Vec::with_capacity(n);
    while gaps.len() < n {
        if gaps.len() + 1 < n && gaps.len() % 11 < 4 {
            let cluster = 4usize.min(n - gaps.len());
            for _ in 0..cluster {
                gaps.push(50 + (rng.next_u32() % 131) as u64);
            }
        } else {
            gaps.push(800 + (rng.next_u32() % 2700) as u64);
        }
    }
    gaps.truncate(n);
    gaps
}

fn wall_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs_f64()
}

fn kill_tree(child: &mut Child) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    if cfg!(windows) {
        let _ = Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    } else {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn ensure_built() {
    let node = debug_bin("aegis-node");
    let client = debug_bin("aegis-client");
    if node.is_file() && client.is_file() {
        return;
    }
    let status = Command::new("cargo")
        .args(["build", "-q", "-p", "aegis-node", "-p", "aegis-client"])
        .current_dir(workspace_root().join("crates"))
        .status()
        .expect("cargo build");
    assert!(status.success(), "cargo build failed");
}

fn spawn_nodes(ports: &[u16]) -> Vec<Child> {
    let node_bin = debug_bin("aegis-node");
    assert!(node_bin.is_file(), "missing {}", node_bin.display());
    let dir = config_dir();
    let mut children = Vec::with_capacity(PATH_LEN);
    for i in 0..PATH_LEN {
        let child = Command::new(&node_bin)
            .args(["--config", &dir.join(format!("node{i}.toml")).to_string_lossy()])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn node");
        children.push(child);
    }
    for &port in ports {
        wait_listen(format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_secs(30));
    }
    children
}

fn run_capture(out_path: &Path) {
    ensure_built();
    let ports = allocate_ports(PATH_LEN);
    let client_cfg = write_configs(&ports);
    let client_bin = debug_bin("aegis-client");
    assert!(client_bin.is_file(), "missing {}", client_bin.display());

    let mut nodes = spawn_nodes(&ports);
    let mut rng = rand_core::OsRng;
    let gaps = bursty_gaps_ms(&mut rng, N_SENDS.saturating_sub(1));
    let mut rows: Vec<(f64, usize, usize)> = Vec::with_capacity(N_SENDS);

    let result = (|| {
        for i in 0..N_SENDS {
            for (idx, node) in nodes.iter_mut().enumerate() {
                if node.try_wait()?.is_some() {
                    panic!("node{idx} exited early during capture");
                }
            }

            let payload_len = 32 + (i * 17) % 225;
            let ts = wall_secs();
            let status = Command::new(&client_bin)
                .args([
                    "--config",
                    &client_cfg.to_string_lossy(),
                    "--payload",
                    &format!("mp-{i}-{payload_len}"),
                    "--raw",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .status()?;
            assert!(status.success(), "client send {i} failed: {status:?}");
            rows.push((ts, payload_len, SPHINX_FRAGMENT_COUNT));

            if i + 1 < N_SENDS {
                thread::sleep(Duration::from_millis(gaps[i]));
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })();

    for node in &mut nodes {
        kill_tree(node);
    }
    result.expect("capture loop");

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("create sim/data");
    }
    let mut f = File::create(out_path).expect("create trace");
    writeln!(f, "timestamp,payload_bytes,cell_count").unwrap();
    writeln!(f, "# vantage=orchestrator_wall_clock_at_client_invoke").unwrap();
    writeln!(
        f,
        "# capture=multiprocess_tcp_testnet path_len={PATH_LEN} n_sends={N_SENDS} ports={ports:?}"
    )
    .unwrap();
    for (ts, payload_bytes, cell_count) in &rows {
        writeln!(f, "{ts:.6},{payload_bytes},{cell_count}").unwrap();
    }

    let duration = rows.last().unwrap().0 - rows.first().unwrap().0;
    eprintln!(
        "wrote {} events ({duration:.1}s span) to {}",
        rows.len(),
        out_path.display()
    );
    assert!(duration >= 5.0);
    assert_eq!(rows.len(), N_SENDS);
}

#[test]
#[ignore = "regenerates sim/data/real_multiprocess_trace.csv; run with --ignored"]
fn capture_multiprocess_burst_trace_to_csv() {
    run_capture(&trace_path());
}
