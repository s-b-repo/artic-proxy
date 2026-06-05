//! Arctic Proxy — a high-performance multi-threaded TCP proxy.
//!
//! Architecture: one OS thread per worker, each pinned to a CPU core (on Linux)
//! and running its own single-threaded Tokio runtime with a dedicated
//! `SO_REUSEPORT` listener. The kernel load-balances incoming connections across
//! the workers, so there is no userspace coordination on the accept path.
//!
//! This layout is what actually makes CPU pinning meaningful: because each
//! worker owns its runtime, the thread that runs the accept loop and all of that
//! worker's connection handlers is the same thread we pinned — Tokio's
//! work-stealing scheduler can't migrate the work onto another core.

use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;

/// How long a worker waits in `accept` before waking to re-check the shutdown
/// flag. Small enough that Ctrl-C feels instant, large enough to be free when
/// idle.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Polling granularity used while draining connections during shutdown.
const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Lower/upper bounds for the userspace relay copy buffer. Tokio's
/// `copy_bidirectional` would otherwise use a fixed 8 KiB buffer regardless of
/// the configured socket buffer size; 64 KiB matches a GRO/GSO superpacket so
/// one read drains a full offloaded segment, and 1 MiB caps per-direction
/// memory at millions of connections.
const MIN_COPY_BUF: usize = 64 * 1024;
const MAX_COPY_BUF: usize = 1024 * 1024;

/// One cache line. Each hot atomic counter is given its own so that a write from
/// one core does not invalidate an unrelated counter sitting in another core's
/// cache (false sharing).
#[repr(align(64))]
struct CachePadded(AtomicU64);

impl CachePadded {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
}

impl std::ops::Deref for CachePadded {
    type Target = AtomicU64;
    fn deref(&self) -> &AtomicU64 {
        &self.0
    }
}

// Each counter lives on its own cache line. `#[repr(align(64))]` on the *struct*
// (as it was originally) only aligns the struct's start — all four atomics still
// shared one line, so every core that bumped any counter invalidated the line
// for every other core. Padding per field is what actually removes the false
// sharing.
struct Stats {
    bytes: CachePadded,
    conns: CachePadded,
    errors: CachePadded,
    rejected: CachePadded,
}

impl Stats {
    fn new() -> Self {
        Self {
            bytes: CachePadded::new(),
            conns: CachePadded::new(),
            errors: CachePadded::new(),
            rejected: CachePadded::new(),
        }
    }
}

/// RAII reservation of a connection slot. Incrementing the live-connection count
/// in a guard whose `Drop` decrements it means the slot is released on *every*
/// exit path — including a panic unwind inside the spawned handler, which a bare
/// `fetch_sub` after the handler would skip. Without this, a single panicking
/// handler permanently leaks a slot, and enough of them drive the proxy to
/// rejecting all traffic (and wedge graceful shutdown, which waits for the count
/// to reach zero).
struct ConnGuard {
    stats: Arc<Stats>,
}

impl ConnGuard {
    /// Reserve a slot, honouring `max_connections` (`0` = unlimited). Returns
    /// `None` if the proxy is already at capacity (the caller should reject).
    fn reserve(stats: &Arc<Stats>, max_connections: u64) -> Option<ConnGuard> {
        if max_connections > 0 {
            let prev = stats.conns.fetch_add(1, Ordering::AcqRel);
            if prev >= max_connections {
                stats.conns.fetch_sub(1, Ordering::AcqRel);
                return None;
            }
        } else {
            stats.conns.fetch_add(1, Ordering::AcqRel);
        }
        Some(ConnGuard {
            stats: Arc::clone(stats),
        })
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.stats.conns.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A `TcpStream` wrapper that tallies every byte it yields from `poll_read` into
/// a shared counter. Wrapping *both* relayed streams in one of these counts each
/// direction exactly once (a byte is counted when it is read out of its source),
/// which (a) feeds a live throughput gauge for long-lived flows and (b) keeps
/// the byte accounting even when the relay ends in an error — both impossible
/// when the total is only read from `copy_bidirectional`'s return value.
struct Counting<'a> {
    inner: TcpStream,
    progress: &'a AtomicU64,
}

impl AsyncRead for Counting<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let n = buf.filled().len() - before;
            if n > 0 {
                self.progress.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        res
    }
}

impl AsyncWrite for Counting<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

struct Config {
    listen_addr: String,
    upstream_addr: String,
    /// Maximum concurrent connections across all workers. `0` means unlimited.
    max_connections: u64,
    num_workers: usize,
    /// Physical CPU id each worker pins to (`cpu_ids[i]` for worker `i`).
    cpu_ids: Vec<usize>,
    connect_timeout_secs: u64,
    buffer_size: u32,
    backlog: i32,
    /// Deprecated: previously slept the accept loop when rejecting. Retained only
    /// so existing positional argument lists keep their meaning; ignored.
    reject_sleep_ms: u64,
    shutdown_drain_secs: u64,
    upstream_test_timeout_secs: u64,
    /// Close a relayed connection that transfers no bytes for this long. `0`
    /// disables it. The data-phase defence against slowloris-style slot
    /// exhaustion that connect_timeout (handshake only) does not cover.
    idle_timeout_secs: u64,
    /// Hard cap on a single connection's total lifetime. `0` disables it.
    max_lifetime_secs: u64,
}

fn main() -> io::Result<()> {
    let config = Arc::new(parse_config()?);

    if config.reject_sleep_ms > 0 {
        eprintln!(
            "⚠️  reject_sleep_ms is deprecated and ignored: sleeping the single-threaded \
             accept loop throttled the proxy's own recovery under overload."
        );
    }

    // Verify the upstream is reachable before we start accepting traffic. This
    // runs on a throwaway single-threaded runtime so the rest of `main` can stay
    // synchronous.
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(test_upstream(&config))?;
    }

    print_banner(&config);

    let stats = Arc::new(Stats::new());
    let shutdown = Arc::new(AtomicBool::new(false));

    // Each worker reports the result of binding its listener so that bind
    // failures (port in use, permission denied, ...) surface immediately instead
    // of leaving us "running" with no listeners.
    let (ready_tx, ready_rx) = mpsc::channel::<io::Result<()>>();

    // One dedicated, CPU-pinned thread per worker, each with its own runtime.
    let mut workers = Vec::with_capacity(config.num_workers);
    for (worker_idx, &cpu_id) in config.cpu_ids.iter().enumerate() {
        let config = Arc::clone(&config);
        let stats = Arc::clone(&stats);
        let shutdown = Arc::clone(&shutdown);
        let ready_tx = ready_tx.clone();
        let handle = std::thread::Builder::new()
            .name(format!("arctic-worker-{worker_idx}"))
            .spawn(move || worker_thread(worker_idx, cpu_id, config, stats, shutdown, ready_tx))?;
        workers.push(handle);
    }
    // Drop our own sender so the channel closes once every worker has reported.
    drop(ready_tx);

    // Wait for every worker to attempt its bind. If any failed, shut the rest
    // down and exit with the error.
    let mut bind_error: Option<io::Error> = None;
    for _ in 0..config.num_workers {
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                eprintln!("❌ Worker failed to start: {e}");
                bind_error.get_or_insert(e);
            }
            // A worker panicked before reporting; its JoinHandle will surface it.
            Err(_) => break,
        }
    }
    if let Some(e) = bind_error {
        shutdown.store(true, Ordering::Release);
        for handle in workers {
            let _ = handle.join();
        }
        return Err(e);
    }

    // The main thread supervises: it prints live stats and waits for Ctrl-C,
    // then drives the drain countdown.
    let supervisor_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    supervisor_rt.block_on(supervise(
        Arc::clone(&stats),
        Arc::clone(&shutdown),
        config.shutdown_drain_secs,
    ));

    // Ctrl-C received and the drain window has elapsed: workers are finishing up.
    // Joining their threads blocks until each has drained (or hit its deadline).
    for handle in workers {
        if handle.join().is_err() {
            eprintln!("⚠️  A worker thread terminated abnormally");
        }
    }

    let remaining = stats.conns.load(Ordering::Acquire);
    if remaining > 0 {
        println!("⚠️  Shutdown timeout reached, {remaining} connection(s) forcibly closed");
    }
    println!("✅ Shutdown complete");
    Ok(())
}

fn parse_config() -> io::Result<Config> {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(String::as_str).unwrap_or("arctic-proxy");

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_usage(prog);
        std::process::exit(0);
    }

    let listen_addr = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());

    let upstream_addr = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:80".to_string());

    let max_connections = parse_arg(&args, 3, 100_000)?;
    let connect_timeout_secs = parse_arg(&args, 4, 5)?;
    let buffer_size: u32 = parse_arg(&args, 5, 65_536)?;
    let backlog: i32 = parse_arg(&args, 6, 4_096)?;
    // Default 0: the old default (10ms) silently throttled accepts under overload.
    let reject_sleep_ms = parse_arg(&args, 7, 0)?;
    let shutdown_drain_secs = parse_arg(&args, 8, 5)?;
    let upstream_test_timeout_secs = parse_arg(&args, 9, 3)?;
    let idle_timeout_secs = parse_arg(&args, 10, 0)?;
    let max_lifetime_secs = parse_arg(&args, 11, 0)?;

    // Validate the listen address up front so we fail fast with a clear message
    // rather than once inside each worker.
    if listen_addr.parse::<SocketAddr>().is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid listen address '{listen_addr}' (expected e.g. 0.0.0.0:8080)"),
        ));
    }

    // `setsockopt(SO_*BUF)` takes a C int, so an oversized buffer would wrap to a
    // negative value and be rejected. Clamp it to a sane, representable range.
    let buffer_size = buffer_size.clamp(1_024, i32::MAX as u32);
    let backlog = backlog.max(1);

    // Worker placement: pin one worker per CPU we are actually *allowed* to run
    // on. Reading the affinity mask (rather than assuming CPUs `0..N`) is what
    // makes pinning correct under a cgroup/cpuset — e.g. a container pinned to
    // CPUs 64..127 — instead of every worker failing to pin to a CPU it can't use.
    let allowed = allowed_cpus();
    let detected = if !allowed.is_empty() {
        allowed.len()
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    };
    let num_workers = std::env::var("ARCTIC_WORKERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(detected)
        .max(1);
    let cpu_ids: Vec<usize> = if allowed.is_empty() {
        (0..num_workers).collect()
    } else {
        // If ARCTIC_WORKERS asks for more workers than allowed CPUs, wrap so two
        // workers can share a core rather than pinning to a forbidden one.
        (0..num_workers).map(|i| allowed[i % allowed.len()]).collect()
    };

    Ok(Config {
        listen_addr,
        upstream_addr,
        max_connections,
        num_workers,
        cpu_ids,
        connect_timeout_secs,
        buffer_size,
        backlog,
        reject_sleep_ms,
        shutdown_drain_secs,
        upstream_test_timeout_secs,
        idle_timeout_secs,
        max_lifetime_secs,
    })
}

/// CPUs the process is permitted to run on, from the scheduler affinity mask.
/// Empty when unavailable (non-Linux, or the query failed), in which case the
/// caller falls back to `available_parallelism`.
#[cfg(target_os = "linux")]
fn allowed_cpus() -> Vec<usize> {
    // SAFETY: `set` is a plain bitset valid when zero-initialized; the call reads
    // exactly `size_of::<cpu_set_t>()` bytes, and `CPU_ISSET` only inspects it.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) != 0 {
            return Vec::new();
        }
        (0..libc::CPU_SETSIZE as usize)
            .filter(|&cpu| libc::CPU_ISSET(cpu, &set))
            .collect()
    }
}

#[cfg(not(target_os = "linux"))]
fn allowed_cpus() -> Vec<usize> {
    Vec::new()
}

/// Parse a positional argument, returning a clear error (instead of silently
/// falling back to the default) when it is present but malformed.
fn parse_arg<T>(args: &[String], idx: usize, default: T) -> io::Result<T>
where
    T: std::str::FromStr,
{
    match args.get(idx) {
        None => Ok(default),
        Some(raw) => raw.parse::<T>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("could not parse argument #{idx} ('{raw}')"),
            )
        }),
    }
}

fn print_usage(prog: &str) {
    println!(
        "Arctic Proxy — high-performance TCP proxy\n\n\
         Usage:\n  {prog} <listen_addr> <upstream_addr> [max_connections] [timeout_secs] \
         [buffer_size] [backlog] [reject_sleep_ms] [shutdown_drain_secs] [upstream_test_timeout_secs] \
         [idle_timeout_secs] [max_lifetime_secs]\n\n\
         Example:\n  {prog} 0.0.0.0:8080 127.0.0.1:80 100000 5 65536 4096 0 5 3 300 0\n\n\
         Notes:\n  \
         - max_connections = 0 means unlimited.\n  \
         - idle_timeout_secs = 0 disables the idle timeout; set it (e.g. 300) on \
         untrusted/edge deployments to reap slow-loris connections.\n  \
         - max_lifetime_secs = 0 disables the hard connection-lifetime cap.\n  \
         - reject_sleep_ms is deprecated and ignored.\n  \
         - Set ARCTIC_WORKERS to override the worker/CPU count (default: all allowed CPUs)."
    );
}

async fn test_upstream(config: &Config) -> io::Result<()> {
    println!("🔍 Testing upstream {}...", config.upstream_addr);
    match tokio::time::timeout(
        Duration::from_secs(config.upstream_test_timeout_secs),
        TcpStream::connect(&config.upstream_addr),
    )
    .await
    {
        Ok(Ok(_)) => {
            println!("✅ Upstream reachable");
            Ok(())
        }
        Ok(Err(e)) => {
            eprintln!("❌ Cannot connect to upstream '{}': {e}", config.upstream_addr);
            print_usage(
                std::env::args()
                    .next()
                    .as_deref()
                    .unwrap_or("arctic-proxy"),
            );
            Err(e)
        }
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "upstream '{}' did not answer within {}s",
                config.upstream_addr, config.upstream_test_timeout_secs
            ),
        )),
    }
}

fn print_banner(config: &Config) {
    let max_conns = if config.max_connections == 0 {
        "unlimited".to_string()
    } else {
        config.max_connections.to_string()
    };
    let fmt_secs = |s: u64| {
        if s == 0 {
            "disabled".to_string()
        } else {
            format!("{s}s")
        }
    };
    println!();
    println!("🚀 HIGH-PERFORMANCE TCP PROXY");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📡 Listen:      {}", config.listen_addr);
    println!("🎯 Upstream:    {}", config.upstream_addr);
    println!(
        "🧵 Workers:     {}{}",
        config.num_workers,
        if cfg!(target_os = "linux") {
            " (CPU-pinned)"
        } else {
            ""
        }
    );
    println!("🔒 Max conns:   {max_conns}");
    println!("⏱️  Conn t/o:    {}s", config.connect_timeout_secs);
    println!("💤 Idle t/o:    {}", fmt_secs(config.idle_timeout_secs));
    println!("🪓 Max life:    {}", fmt_secs(config.max_lifetime_secs));
    println!("📦 Buffer size: {} bytes", config.buffer_size);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
}

/// Entry point for a worker OS thread: pin to a CPU, build a single-threaded
/// runtime, bind the listener, and run the accept loop until shutdown.
fn worker_thread(
    worker_idx: usize,
    cpu_id: usize,
    config: Arc<Config>,
    stats: Arc<Stats>,
    shutdown: Arc<AtomicBool>,
    ready_tx: mpsc::Sender<io::Result<()>>,
) {
    #[cfg(target_os = "linux")]
    if let Err(e) = pin_to_cpu(cpu_id) {
        eprintln!("⚠️  Worker {worker_idx} could not pin to CPU {cpu_id}: {e}");
    }

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };

    rt.block_on(async move {
        let listener = match create_listener(
            &config.listen_addr,
            config.buffer_size as usize,
            config.backlog,
            cpu_id,
        ) {
            Ok(listener) => {
                let _ = ready_tx.send(Ok(()));
                listener
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };
        // Release the channel so `main` can detect that all workers have
        // reported even if some never reach this point.
        drop(ready_tx);

        println!("✅ Worker {worker_idx} ready on CPU {cpu_id}");
        accept_loop(worker_idx, listener, &config, &stats, &shutdown).await;
        drain_connections(&stats, config.shutdown_drain_secs).await;
    });
}

async fn accept_loop(
    worker_idx: usize,
    listener: TcpListener,
    config: &Config,
    stats: &Arc<Stats>,
    shutdown: &Arc<AtomicBool>,
) {
    // Share the upstream address cheaply across every spawned handler.
    let upstream: Arc<str> = Arc::from(config.upstream_addr.as_str());

    while !shutdown.load(Ordering::Acquire) {
        // Wake periodically even if no connection arrives, so we notice the
        // shutdown flag promptly instead of blocking forever in `accept`.
        let accepted = match tokio::time::timeout(ACCEPT_POLL_INTERVAL, listener.accept()).await {
            Ok(result) => result,
            Err(_elapsed) => continue,
        };

        match accepted {
            Ok((client, peer)) => {
                // Reserve a slot only now that we actually have a connection. The
                // guard releases it on every exit path of the spawned task,
                // including a panic unwind.
                let guard = match ConnGuard::reserve(stats, config.max_connections) {
                    Some(guard) => guard,
                    None => {
                        stats.rejected.fetch_add(1, Ordering::Relaxed);
                        // Abrupt close is fine for a rejected client. No sleep:
                        // stalling the accept loop only slows our own recovery.
                        drop(client);
                        continue;
                    }
                };

                let upstream = Arc::clone(&upstream);
                let stats = Arc::clone(stats);
                let connect_timeout = config.connect_timeout_secs;
                let buffer_size = config.buffer_size;
                let idle = config.idle_timeout_secs;
                let lifetime = config.max_lifetime_secs;

                tokio::spawn(async move {
                    // Holding the guard in the task ties slot release to the task's
                    // lifetime — it runs even if `handle_connection` panics.
                    let _guard = guard;
                    match handle_connection(
                        client,
                        &upstream,
                        peer,
                        connect_timeout,
                        buffer_size,
                        idle,
                        lifetime,
                        &stats,
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(e) if is_benign(&e) => {
                            // A peer hanging up is normal traffic, not a fault.
                        }
                        Err(_) => {
                            stats.errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
            Err(e) => {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("⚠️  Worker {worker_idx} accept error: {e}");
                // File-descriptor exhaustion would otherwise spin this loop at
                // 100% CPU; back off briefly to let connections close.
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOBUFS) | Some(libc::ENOMEM)
                ) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }
}

/// Wait for in-flight connections to finish, up to `drain_secs`. The worker's
/// own runtime keeps driving its spawned handlers while we poll.
async fn drain_connections(stats: &Arc<Stats>, drain_secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(drain_secs);
    while stats.conns.load(Ordering::Acquire) > 0 {
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
    }
}

fn create_listener(
    addr: &str,
    buffer_size: usize,
    backlog: i32,
    cpu_id: usize,
) -> io::Result<TcpListener> {
    let socket_addr: SocketAddr = addr
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // Create the socket with SO_REUSEPORT *before* binding so every worker can
    // bind the same address and let the kernel balance accepts between them.
    let socket = Socket::new(
        if socket_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::STREAM,
        Some(Protocol::TCP),
    )?;

    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    // Bind a v6 wildcard as v6-only so it doesn't also claim the v4 space;
    // keeps the bound family matching the requested address. Best effort.
    if socket_addr.is_ipv6() {
        if let Err(e) = socket.set_only_v6(true) {
            eprintln!("⚠️  Could not set IPV6_V6ONLY: {e}");
        }
    }

    if let Err(e) = socket.set_recv_buffer_size(buffer_size) {
        eprintln!("⚠️  Could not set listener recv buffer size: {e}");
    }
    if let Err(e) = socket.set_send_buffer_size(buffer_size) {
        eprintln!("⚠️  Could not set listener send buffer size: {e}");
    }

    socket.bind(&socket_addr.into())?;
    socket.listen(backlog)?;

    let std_listener: std::net::TcpListener = socket.into();
    // `from_std` registers the fd with the reactor; it must run inside a runtime,
    // which it does (this is called from within `block_on`).
    let listener = TcpListener::from_std(std_listener)?;

    // TCP_FASTOPEN, TCP_DEFER_ACCEPT and SO_INCOMING_CPU have no socket2 wrapper,
    // so they are set via libc. All best-effort accelerators on Linux: failing to
    // set them leaves the proxy fully functional, just without those optimizations.
    #[cfg(target_os = "linux")]
    set_linux_listener_opts(&listener, backlog, cpu_id);

    Ok(listener)
}

/// Best-effort Linux-only listener accelerators not exposed by socket2.
///
/// # Safety
/// Each `setsockopt` reads exactly `size_of_val(&opt)` bytes from a live local
/// `c_int`, which matches what the kernel expects for these integer options.
#[cfg(target_os = "linux")]
fn set_linux_listener_opts(listener: &TcpListener, backlog: i32, cpu_id: usize) {
    let fd = listener.as_raw_fd();
    let set = |level: libc::c_int, name: libc::c_int, value: libc::c_int, label: &str| {
        // SAFETY: `&value` points to a live `c_int` and the length is its exact
        // size; `fd` is owned by `listener` and valid for this call.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if rc != 0 {
            eprintln!("⚠️  Could not set {label}: {}", io::Error::last_os_error());
        }
    };

    // TCP_FASTOPEN: accept data carried in the SYN to cut a round trip.
    set(libc::IPPROTO_TCP, libc::TCP_FASTOPEN, backlog, "TCP_FASTOPEN");
    // TCP_DEFER_ACCEPT: don't wake the accept loop until the client sends data.
    set(libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT, 1, "TCP_DEFER_ACCEPT");
    // SO_INCOMING_CPU: bias this REUSEPORT listener toward connections whose RX
    // softirq landed on the worker's own core, so accept + handler + NIC queue
    // share a cache. Pair with NIC RSS/IRQ affinity for full effect.
    if let Ok(cpu) = libc::c_int::try_from(cpu_id) {
        set(libc::SOL_SOCKET, libc::SO_INCOMING_CPU, cpu, "SO_INCOMING_CPU");
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    client: TcpStream,
    upstream_addr: &str,
    peer: SocketAddr,
    connect_timeout: u64,
    buffer_size: u32,
    idle_secs: u64,
    lifetime_secs: u64,
    stats: &Stats,
) -> io::Result<()> {
    let upstream = match tokio::time::timeout(
        Duration::from_secs(connect_timeout),
        TcpStream::connect(upstream_addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("upstream '{upstream_addr}' timed out connecting on behalf of {peer}"),
            ));
        }
    };

    // Best-effort per-connection tuning; never fatal.
    optimize_socket(&client, buffer_size);
    optimize_socket(&upstream, buffer_size);

    // Size the userspace relay buffer from the configured buffer size (clamped),
    // instead of tokio's fixed 8 KiB — fewer read/write syscalls per byte moved.
    let copy_buf = (buffer_size as usize).clamp(MIN_COPY_BUF, MAX_COPY_BUF);

    // Per-connection byte counter, updated live by both wrapped streams.
    let progress = AtomicU64::new(0);
    let mut client = Counting {
        inner: client,
        progress: &progress,
    };
    let mut upstream = Counting {
        inner: upstream,
        progress: &progress,
    };

    let copy = io::copy_bidirectional_with_sizes(&mut client, &mut upstream, copy_buf, copy_buf);

    // Fast path: no idle/lifetime caps configured — just relay, then publish the
    // byte total (including any moved before an error, which the old code lost).
    if idle_secs == 0 && lifetime_secs == 0 {
        let res = copy.await;
        stats.bytes.fetch_add(progress.load(Ordering::Relaxed), Ordering::Relaxed);
        return res.map(|_| ());
    }

    // Watchdog path: a single per-connection timer (granularity = the idle, else
    // lifetime, window) flushes the byte counter and enforces the caps. Cheaper
    // than wrapping every read in a timeout, which churns a timer per read.
    tokio::pin!(copy);
    let start = Instant::now();
    let mut last_flushed: u64 = 0;
    let mut last_progress: u64 = 0;
    let window = Duration::from_secs(if idle_secs > 0 { idle_secs } else { lifetime_secs });
    let mut ticker = tokio::time::interval(window);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            biased;
            res = &mut copy => {
                let moved = progress.load(Ordering::Relaxed);
                stats.bytes.fetch_add(moved.saturating_sub(last_flushed), Ordering::Relaxed);
                return res.map(|_| ());
            }
            _ = ticker.tick() => {
                let moved = progress.load(Ordering::Relaxed);
                stats.bytes.fetch_add(moved.saturating_sub(last_flushed), Ordering::Relaxed);
                last_flushed = moved;

                if lifetime_secs > 0 && start.elapsed() >= Duration::from_secs(lifetime_secs) {
                    return Ok(()); // hard lifetime cap reached; drop closes both sides
                }
                if idle_secs > 0 && moved == last_progress {
                    return Ok(()); // no bytes moved this window: idle, reap the slot
                }
                last_progress = moved;
            }
        }
    }
}

/// `true` for errors that just mean "the other end went away" — expected on a
/// busy proxy and not worth counting as a fault.
fn is_benign(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof | NotConnected
    )
}

/// Apply latency/throughput tuning to an established connection. All options are
/// best effort: a failure is logged but never aborts the connection.
fn optimize_socket(stream: &TcpStream, buffer_size: u32) {
    let sock = SockRef::from(stream);

    // TCP_NODELAY: disable Nagle for low latency.
    if let Err(e) = sock.set_tcp_nodelay(true) {
        eprintln!("⚠️  Could not set TCP_NODELAY: {e}");
    }

    // Aggressive keepalive so a dead or half-open peer is reaped in ~30s instead
    // of the kernel's 2-hour default — bounds how long a stuck connection can pin
    // a slot, a file descriptor, and kernel socket buffers.
    let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(15));
    #[cfg(target_os = "linux")]
    let keepalive = keepalive
        .with_interval(Duration::from_secs(5))
        .with_retries(3);
    if let Err(e) = sock.set_tcp_keepalive(&keepalive) {
        eprintln!("⚠️  Could not set SO_KEEPALIVE params: {e}");
    }

    // Size the socket buffers. The accepted client socket inherits these from
    // the listener, but the freshly-connected upstream socket does not, so we
    // apply them on both for symmetric throughput tuning.
    let buffer_size = buffer_size as usize;
    if let Err(e) = sock.set_recv_buffer_size(buffer_size) {
        eprintln!("⚠️  Could not set SO_RCVBUF: {e}");
    }
    if let Err(e) = sock.set_send_buffer_size(buffer_size) {
        eprintln!("⚠️  Could not set SO_SNDBUF: {e}");
    }

    #[cfg(target_os = "linux")]
    {
        // TCP_QUICKACK: send ACKs immediately. The kernel resets this after one
        // ACK, so it is a hint rather than a sticky mode.
        if let Err(e) = sock.set_tcp_quickack(true) {
            eprintln!("⚠️  Could not set TCP_QUICKACK: {e}");
        }

        // TCP_USER_TIMEOUT: cap how long transmitted data may stay unacknowledged
        // before the kernel tears the connection down, independent of keepalive.
        // Catches a peer that vanishes mid-transfer while data is in flight.
        let fd = stream.as_raw_fd();
        let timeout_ms: libc::c_int = 30_000;
        // SAFETY: `&timeout_ms` is a live `c_int`; the length is its exact size;
        // `fd` is owned by `stream` and valid for this call.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                &timeout_ms as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&timeout_ms) as libc::socklen_t,
            )
        };
        if rc != 0 {
            eprintln!(
                "⚠️  Could not set TCP_USER_TIMEOUT: {}",
                io::Error::last_os_error()
            );
        }
    }

    // NOTE: we deliberately do *not* set SO_LINGER(0) here. An abortive RST
    // close can discard data still queued in the send buffer, which for a proxy
    // means silently truncating a response. Graceful FIN close is the correct
    // default; rely on net.ipv4.tcp_tw_reuse to manage TIME_WAIT churn.
}

async fn report_stats(stats: Arc<Stats>, shutdown: Arc<AtomicBool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let mut last_bytes = 0u64;
    let mut last_tick = Instant::now();

    loop {
        interval.tick().await;
        if shutdown.load(Ordering::Acquire) {
            break;
        }

        let bytes = stats.bytes.load(Ordering::Acquire);
        let conns = stats.conns.load(Ordering::Acquire);
        let errors = stats.errors.load(Ordering::Acquire);
        let rejected = stats.rejected.load(Ordering::Acquire);

        // Divide by the real elapsed time, not an assumed 1.000s, so a late tick
        // under load doesn't inflate the reported rate.
        let now = Instant::now();
        let elapsed = now.duration_since(last_tick).as_secs_f64().max(1e-9);
        last_tick = now;

        let bytes_diff = bytes.saturating_sub(last_bytes);
        last_bytes = bytes;

        let gbps = (bytes_diff * 8) as f64 / 1_000_000_000.0 / elapsed;
        let total_gb = bytes as f64 / 1_000_000_000.0;

        println!(
            "⚡ {conns:6} active | {errors:6} err | {rejected:6} rej | {gbps:7.2} Gbps | {total_gb:9.2} GB total"
        );
    }
}

/// Print live stats and wait for Ctrl-C, then signal shutdown and show a drain
/// countdown until connections finish or the grace period elapses.
async fn supervise(stats: Arc<Stats>, shutdown: Arc<AtomicBool>, drain_secs: u64) {
    let reporter = tokio::spawn(report_stats(Arc::clone(&stats), Arc::clone(&shutdown)));

    let _ = signal::ctrl_c().await;
    println!("\n🛑 Shutting down gracefully...");
    shutdown.store(true, Ordering::Release);
    reporter.abort();

    let deadline = Instant::now() + Duration::from_secs(drain_secs);
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    while stats.conns.load(Ordering::Acquire) > 0 && Instant::now() < deadline {
        tick.tick().await;
        print!(".");
        let _ = std::io::stdout().flush();
    }
    println!();
}

/// Pin the calling thread to a single CPU core for cache locality. Linux only;
/// the only call site is `#[cfg(target_os = "linux")]`, so no stub is needed
/// elsewhere.
///
/// # Safety
/// `cpu_set_t` is a plain bitset that is valid when zero-initialized, and the
/// `CPU_SET`/`sched_setaffinity` calls read exactly the buffer we pass with its
/// stated size, so the FFI is sound.
#[cfg(target_os = "linux")]
fn pin_to_cpu(cpu_id: usize) -> io::Result<()> {
    // `cpu_set_t` / `CPU_SET` only address CPUs `0..CPU_SETSIZE` (1024 with
    // glibc); writing a higher index is out of bounds, so refuse it rather than
    // corrupt memory.
    if cpu_id >= libc::CPU_SETSIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("CPU id {cpu_id} exceeds CPU_SETSIZE ({})", libc::CPU_SETSIZE),
        ));
    }
    // SAFETY: see the function's `# Safety` note above; `cpu_id` is bounds-checked.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu_id, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
