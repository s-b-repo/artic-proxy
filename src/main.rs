use std::os::unix::io::AsRawFd;
use tokio::net::{TcpListener, TcpStream};
use tokio::io;
use tokio::signal;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::Duration;
use std::net::SocketAddr;
use futures::future;
use socket2::{Socket, Domain, Type, Protocol};
use std::io::{self as stdio, Write};

// Cache-aligned stats to prevent false sharing
#[repr(align(64))]
struct Stats {
    bytes: AtomicU64,
    conns: AtomicU64,
    errors: AtomicU64,
    rejected: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            bytes: AtomicU64::new(0),
            conns: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        }
    }
}

struct Config {
    listen_addr: String,
    upstream_addr: String,
    max_connections: u64,
    num_workers: usize,
    connect_timeout_secs: u64,
    buffer_size: u32,
    backlog: i32,
    reject_sleep_ms: u64,
    shutdown_drain_secs: u64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> io::Result<()> {
    // Parse config
    let config = parse_config().await?;

    let stats = Arc::new(Stats::new());
    let shutdown = Arc::new(AtomicBool::new(false));

    // Stats reporter
    let stats_task = tokio::spawn(report_stats(Arc::clone(&stats), Arc::clone(&shutdown)));

    // Graceful shutdown handler
    let shutdown_clone = Arc::clone(&shutdown);
    let shutdown_task = tokio::spawn(shutdown_handler(shutdown_clone, config.shutdown_drain_secs));

    // Spawn listener per CPU with SO_REUSEPORT for kernel load balancing
    let mut handles = vec![];
    for cpu_id in 0..config.num_workers {
        let upstream = config.upstream_addr.clone();
        let listen = config.listen_addr.clone();
        let stats = Arc::clone(&stats);
        let shutdown = Arc::clone(&shutdown);
        let max_conns = config.max_connections;
        let timeout = config.connect_timeout_secs;
        let bufsize = config.buffer_size;
        let backlog = config.backlog;
        let reject_sleep = config.reject_sleep_ms;

        let handle = tokio::spawn(async move {
            if let Err(e) = run_listener(&listen, &upstream, cpu_id, stats, shutdown, max_conns, timeout, bufsize, backlog, reject_sleep).await {
                eprintln!("Worker {} error: {}", cpu_id, e);
            }
        });
        handles.push(handle);
    }

    // Wait for all listeners
    future::join_all(handles).await;

    // Wait for shutdown task which handles draining
    let _ = shutdown_task.await;

    // Ensure all connections are drained
    let max_drain_wait = Duration::from_secs(config.shutdown_drain_secs);
    let start = std::time::Instant::now();
    loop {
        if stats.conns.load(Ordering::Acquire) == 0 {
            break;
        }
        if start.elapsed() > max_drain_wait {
            println!("⚠️ Shutdown timeout reached, {} connections remaining", stats.conns.load(Ordering::Acquire));
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Wait for stats task
    let _ = stats_task.await;

    println!("✅ Shutdown complete");
    Ok(())
}

async fn parse_config() -> io::Result<Config> {
    let args: Vec<String> = std::env::args().collect();

    let listen_addr = args.get(1)
    .map(|s| s.to_string())
    .unwrap_or_else(|| "0.0.0.0:8080".to_string());

    let upstream_addr = args.get(2)
    .map(|s| s.to_string())
    .unwrap_or_else(|| "127.0.0.1:80".to_string());

    let max_connections = args.get(3)
    .and_then(|s| s.parse().ok())
    .unwrap_or(100000);

    let connect_timeout_secs = args.get(4)
    .and_then(|s| s.parse().ok())
    .unwrap_or(5);

    let buffer_size: u32 = args.get(5)
    .and_then(|s| s.parse().ok())
    .unwrap_or(65536);

    let backlog: i32 = args.get(6)
    .and_then(|s| s.parse().ok())
    .unwrap_or(4096);

    let reject_sleep_ms = args.get(7)
    .and_then(|s| s.parse().ok())
    .unwrap_or(10);

    let shutdown_drain_secs = args.get(8)
    .and_then(|s| s.parse().ok())
    .unwrap_or(5);

    let upstream_test_timeout_secs = args.get(9)
    .and_then(|s| s.parse().ok())
    .unwrap_or(3);

    let num_workers = std::thread::available_parallelism()
    .map(|n| n.get())
    .unwrap_or(4);

    // Test upstream connectivity
    println!("🔍 Testing upstream {}...", upstream_addr);
    match tokio::time::timeout(
        Duration::from_secs(upstream_test_timeout_secs),
                               TcpStream::connect(&upstream_addr)
    ).await {
        Ok(Ok(_)) => println!("✅ Upstream reachable"),
        Ok(Err(e)) => {
            eprintln!("❌ Cannot connect to upstream: {}", e);
            eprintln!("💡 Usage: {} <listen_addr> <upstream_addr> [max_connections] [timeout_secs] [buffer_size] [backlog] [reject_sleep_ms] [shutdown_drain_secs] [upstream_test_timeout_secs]", args[0]);
            eprintln!("   Example: {} 0.0.0.0:8080 127.0.0.1:80 100000 5 65536 4096 10 5 3", args[0]);
            return Err(e);
        }
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "upstream timeout"
            ));
        }
    }

    println!();
    println!("🚀 HIGH-PERFORMANCE TCP PROXY");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📡 Listen:      {}", listen_addr);
    println!("🎯 Upstream:    {}", upstream_addr);
    println!("🧵 Workers:     {}{}", num_workers,
             if cfg!(target_os = "linux") { " (CPU-pinned)" } else { "" });
    println!("🔒 Max conns:   {}", max_connections);
    println!("⏱️  Timeout:     {}s", connect_timeout_secs);
    println!("📦 Buffer size: {} bytes", buffer_size);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    Ok(Config {
        listen_addr,
       upstream_addr,
       max_connections,
       num_workers,
       connect_timeout_secs,
       buffer_size,
       backlog,
       reject_sleep_ms,
       shutdown_drain_secs,
    })
}

async fn run_listener(
    listen_addr: &str,
    upstream: &str,
    cpu_id: usize,
    stats: Arc<Stats>,
    shutdown: Arc<AtomicBool>,
    max_connections: u64,
    connect_timeout: u64,
    buffer_size: u32,
    backlog: i32,
    reject_sleep_ms: u64,
) -> io::Result<()> {
    // Pin this task to specific CPU
    #[cfg(target_os = "linux")]
    if let Err(e) = pin_to_cpu(cpu_id) {
        eprintln!("⚠️  Worker {} could not pin to CPU {}: {}", cpu_id, cpu_id, e);
    }

    // Create optimized listener with SO_REUSEPORT
    let listener = create_listener(listen_addr, buffer_size as usize, backlog).await?;

    println!("✅ Worker {} ready on CPU {}", cpu_id, cpu_id);

    loop {
        // Check shutdown signal
        if shutdown.load(Ordering::Relaxed) {
            println!("Worker {} shutting down...", cpu_id);
            break;
        }

        // Atomic check-and-increment for connection limit
        let mut current_conns = stats.conns.load(Ordering::Acquire);
        loop {
            if current_conns >= max_connections {
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(reject_sleep_ms)).await;
                current_conns = stats.conns.load(Ordering::Acquire);
                continue;
            }

            match stats.conns.compare_exchange(
                current_conns,
                current_conns + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(new_current) => current_conns = new_current,
            }
        }

        match listener.accept().await {
            Ok((client, peer_addr)) => {
                let upstream = upstream.to_string();
                let stats = Arc::clone(&stats);
                let shutdown = Arc::clone(&shutdown);

                // Spawn connection handler
                tokio::spawn(async move {
                    // Check if we should shutdown immediately
                    if shutdown.load(Ordering::Relaxed) {
                        stats.conns.fetch_sub(1, Ordering::Release);
                        return;
                    }

                    match handle_connection(
                        client,
                        &upstream,
                        peer_addr,
                        connect_timeout,
                        buffer_size,
                    ).await {
                        Ok(bytes) => {
                            stats.bytes.fetch_add(bytes, Ordering::Relaxed);
                        }
                        Err(_) => {
                            stats.errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    stats.conns.fetch_sub(1, Ordering::Release);
                });
            }
            Err(e) => {
                // Decrement since we incremented earlier
                stats.conns.fetch_sub(1, Ordering::Release);
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                eprintln!("Accept error on worker {}: {}", cpu_id, e);
                stats.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    Ok(())
}

async fn create_listener(addr: &str, buffer_size: usize, backlog: i32) -> io::Result<TcpListener> {
    // Parse the address
    let socket_addr: SocketAddr = addr.parse()
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // Create socket with SO_REUSEPORT BEFORE binding
    let socket = Socket::new(
        if socket_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 },
            Type::STREAM,
            Some(Protocol::TCP),
    )?;

    // Set SO_REUSEPORT and SO_REUSEADDR before binding
    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    // Set buffer sizes
    if let Err(e) = socket.set_recv_buffer_size(buffer_size) {
        eprintln!("⚠️  Could not set recv buffer size: {}", e);
    }
    if let Err(e) = socket.set_send_buffer_size(buffer_size) {
        eprintln!("⚠️  Could not set send buffer size: {}", e);
    }

    // Bind
    socket.bind(&socket_addr.into())?;
    socket.listen(backlog)?;

    // Convert to tokio TcpListener
    let std_listener: std::net::TcpListener = socket.into();
    let listener = TcpListener::from_std(std_listener)?;

    let fd = listener.as_raw_fd();

    // Set additional socket options with error checking
    unsafe {
        if socket_addr.is_ipv6() {
            let one: libc::c_int = 1;
            if libc::setsockopt(
                fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t
            ) != 0 {
                eprintln!("⚠️  Could not set IPV6_V6ONLY");
            }
        }

        #[cfg(target_os = "linux")]
        {
            // TCP_FASTOPEN
            let fastopen_backlog: libc::c_int = backlog;
            if libc::setsockopt(
                fd, libc::IPPROTO_TCP, libc::TCP_FASTOPEN,
                &fastopen_backlog as *const _ as *const libc::c_void,
                std::mem::size_of_val(&fastopen_backlog) as libc::socklen_t
            ) != 0 {
                eprintln!("⚠️  Could not set TCP_FASTOPEN");
            }

            // TCP_DEFER_ACCEPT - only accept when data ready
            let timeout: libc::c_int = 1;
            if libc::setsockopt(
                fd, libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of_val(&timeout) as libc::socklen_t
            ) != 0 {
                eprintln!("⚠️  Could not set TCP_DEFER_ACCEPT");
            }
        }
    }

    Ok(listener)
}

async fn handle_connection(
    mut client: TcpStream,
    upstream_addr: &str,
    peer: SocketAddr,
    connect_timeout: u64,
    buffer_size: u32,
) -> io::Result<u64> {
    // Connect with timeout
    let mut upstream = match tokio::time::timeout(
        Duration::from_secs(connect_timeout),
                                                  TcpStream::connect(upstream_addr)
    ).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("upstream timeout connecting from {}", peer)
            ));
        }
    };

    // Optimize both sockets
    if let Err(e) = optimize_socket(&client, buffer_size) {
        eprintln!("⚠️  Could not optimize client socket: {}", e);
    }
    if let Err(e) = optimize_socket(&upstream, buffer_size) {
        eprintln!("⚠️  Could not optimize upstream socket: {}", e);
    }

    // Bidirectional transfer (user-space buffering)
    let (tx, rx) = io::copy_bidirectional(&mut client, &mut upstream).await?;

    Ok(tx + rx)
}

#[inline(always)]
fn optimize_socket(stream: &TcpStream, buffer_size: u32) -> io::Result<()> {
    let fd = stream.as_raw_fd();

    unsafe {
        let one: libc::c_int = 1;

        // TCP_NODELAY - disable Nagle for low latency
        if libc::setsockopt(
            fd, libc::IPPROTO_TCP, libc::TCP_NODELAY,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t
        ) != 0 {
            eprintln!("⚠️  Could not set TCP_NODELAY");
        }

        // TCP_QUICKACK - send ACKs immediately (Linux only)
        #[cfg(target_os = "linux")]
        {
            if libc::setsockopt(
                fd, libc::IPPROTO_TCP, libc::TCP_QUICKACK,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t
            ) != 0 {
                eprintln!("⚠️  Could not set TCP_QUICKACK");
            }
        }

        // Set buffer sizes
        let bufsize: libc::c_int = buffer_size as libc::c_int;
        if libc::setsockopt(
            fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
            &bufsize as *const _ as *const libc::c_void,
            std::mem::size_of_val(&bufsize) as libc::socklen_t
        ) != 0 {
            eprintln!("⚠️  Could not set SO_RCVBUF");
        }
        if libc::setsockopt(
            fd, libc::SOL_SOCKET, libc::SO_SNDBUF,
            &bufsize as *const _ as *const libc::c_void,
            std::mem::size_of_val(&bufsize) as libc::socklen_t
        ) != 0 {
            eprintln!("⚠️  Could not set SO_SNDBUF");
        }

        // SO_KEEPALIVE for health checks
        if libc::setsockopt(
            fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t
        ) != 0 {
            eprintln!("⚠️  Could not set SO_KEEPALIVE");
        }

        // SO_LINGER(0) for instant close
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        if libc::setsockopt(
            fd, libc::SOL_SOCKET, libc::SO_LINGER,
            &linger as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t
        ) != 0 {
            eprintln!("⚠️  Could not set SO_LINGER");
        }
    }

    Ok(())
}

async fn report_stats(stats: Arc<Stats>, shutdown: Arc<AtomicBool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut last_bytes = 0u64;

    loop {
        interval.tick().await;

        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let bytes = stats.bytes.load(Ordering::Acquire);
        let conns = stats.conns.load(Ordering::Acquire);
        let errors = stats.errors.load(Ordering::Acquire);
        let rejected = stats.rejected.load(Ordering::Acquire);

        let bytes_diff = bytes.saturating_sub(last_bytes);
        last_bytes = bytes;

        let gbps = (bytes_diff * 8) as f64 / 1_000_000_000.0;
        let total_gb = bytes as f64 / 1_000_000_000.0;

        println!(
            "⚡ {:6} active | {:6} err | {:6} rej | {:7.2} Gbps | {:9.2} GB total",
            conns, errors, rejected, gbps, total_gb
        );
    }
}

async fn shutdown_handler(shutdown: Arc<AtomicBool>, drain_secs: u64) {
    let _ = signal::ctrl_c().await;
    println!("\n🛑 Shutting down gracefully...");
    shutdown.store(true, Ordering::Release);

    // Give connections time to drain with progress
    let drain_duration = Duration::from_secs(drain_secs);
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    let start = std::time::Instant::now();
    while start.elapsed() < drain_duration {
        interval.tick().await;
        print!(".");
        stdio::stdout().flush().ok();
    }
    println!();
}

#[inline(always)]
#[cfg(target_os = "linux")]
fn pin_to_cpu(cpu_id: usize) -> io::Result<()> {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu_id, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn pin_to_cpu(_cpu_id: usize) -> io::Result<()> {
    Ok(())
}
