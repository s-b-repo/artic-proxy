# 🚀 Arctic Proxy

A blazingly fast, high-performance TCP proxy written in Rust with advanced kernel optimizations and zero-copy networking.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

## ✨ Features

- **🔥 Extreme Performance**: Multi-threaded architecture with CPU pinning and SO_REUSEPORT for kernel-level load balancing
- **⚡ Zero-Copy I/O**: Utilizes Tokio's bidirectional copy for efficient data transfer
- **🎯 Smart Load Balancing**: Kernel-managed connection distribution across CPU cores
- **📊 Real-time Stats**: Live monitoring of throughput, connections, errors, and rejected requests
- **🛡️ Graceful Shutdown**: Proper connection draining with configurable timeout
- **🔧 Highly Configurable**: Fine-tune buffer sizes, connection limits, timeouts, and more
- **💪 Production Ready**: Battle-tested TCP optimizations (TCP_NODELAY, TCP_QUICKACK, TCP_FASTOPEN)

## 🏗️ Architecture

Arctic Proxy spawns one worker per CPU core, each bound to a specific CPU for optimal cache locality. The kernel distributes incoming connections across workers using SO_REUSEPORT, ensuring efficient load balancing without userspace coordination overhead.

```
Client → [Worker 0 (CPU 0)] → Upstream
      → [Worker 1 (CPU 1)] → Upstream
      → [Worker 2 (CPU 2)] → Upstream
      → [Worker N (CPU N)] → Upstream
```

## 📦 Installation

### Prerequisites

- Rust 1.70 or higher
- Linux (recommended for full feature support)
- `libc` for low-level socket operations

### Build from Source

```
git clone https://github.com/yourusername/arctic-proxy.git
cd arctic-proxy
cargo build --release
```

The compiled binary will be available at `target/release/arctic-proxy`.

## 🚀 Quick Start

### Basic Usage

```
# Proxy from port 8080 to localhost:80
cargo run --release -- 0.0.0.0:8080 127.0.0.1:80

# Or use the compiled binary
./target/release/arctic-proxy 0.0.0.0:8080 127.0.0.1:80
```

### Advanced Configuration

```
arctic-proxy <listen_addr> <upstream_addr> [max_connections] [timeout_secs] [buffer_size] [backlog] [reject_sleep_ms] [shutdown_drain_secs] [upstream_test_timeout_secs]
```

**Example:**
```
arctic-proxy 0.0.0.0:8080 127.0.0.1:80 100000 5 65536 4096 10 5 3
```

## ⚙️ Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `listen_addr` | `0.0.0.0:8080` | Address to listen on |
| `upstream_addr` | `127.0.0.1:80` | Upstream server address |
| `max_connections` | `100000` | Maximum concurrent connections |
| `timeout_secs` | `5` | Connection timeout in seconds |
| `buffer_size` | `65536` | Socket buffer size in bytes |
| `backlog` | `4096` | TCP listen backlog |
| `reject_sleep_ms` | `10` | Sleep duration when rejecting connections |
| `shutdown_drain_secs` | `5` | Grace period for connection draining |
| `upstream_test_timeout_secs` | `3` | Upstream connectivity test timeout |

## 📊 Real-time Monitoring

Arctic Proxy provides live statistics every second:

```
⚡    234 active |      12 err |       5 rej |    2.45 Gbps |     15.67 GB total
```

- **active**: Current active connections
- **err**: Total connection errors
- **rej**: Rejected connections (when max limit reached)
- **Gbps**: Current throughput in gigabits per second
- **GB total**: Total data transferred

## 🔧 Performance Tuning

### System-level Optimizations

For maximum performance on Linux, tune these kernel parameters:

```
# Increase connection tracking
sudo sysctl -w net.netfilter.nf_conntrack_max=1000000

# Increase file descriptor limits
ulimit -n 1000000

# TCP tuning
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -w net.ipv4.tcp_fin_timeout=30
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535

# Buffer sizes
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
```

### Application-level Tuning

Adjust these parameters based on your workload:

- **High throughput**: Increase `buffer_size` to 128KB or 256KB
- **Low latency**: Keep default `buffer_size` (64KB) and ensure TCP_NODELAY is enabled
- **Many connections**: Increase `max_connections` and `backlog`
- **Resource constrained**: Reduce `num_workers` by limiting available CPUs

## 🛠️ Technical Details

### Socket Optimizations

- **SO_REUSEPORT**: Kernel-level load balancing across worker threads
- **TCP_NODELAY**: Disable Nagle's algorithm for low latency
- **TCP_QUICKACK**: Send ACKs immediately (Linux)
- **TCP_FASTOPEN**: Reduce connection setup latency
- **TCP_DEFER_ACCEPT**: Only accept connections with data ready
- **SO_KEEPALIVE**: Detect dead connections
- **SO_LINGER(0)**: Instant socket closure

### Memory Efficiency

- Cache-aligned atomic counters to prevent false sharing
- Zero-copy bidirectional data transfer with `copy_bidirectional`
- Efficient buffer reuse through Tokio's runtime

### Concurrency Model

- Multi-threaded Tokio runtime with one worker per CPU
- CPU affinity pinning for cache locality (Linux)
- Lock-free atomic operations for connection counting
- Compare-and-swap for connection limit enforcement

## 🔒 Graceful Shutdown

Arctic Proxy handles `SIGINT` (Ctrl+C) gracefully:

1. Stops accepting new connections
2. Waits for existing connections to complete (configurable timeout)
3. Reports remaining connections after timeout
4. Cleans up resources and exits

```
^C
🛑 Shutting down gracefully...
......
⚠️ Shutdown timeout reached, 12 connections remaining
✅ Shutdown complete
```

## 🐛 Troubleshooting

### "Cannot connect to upstream"

Ensure the upstream server is running and accessible:

```
# Test connectivity
telnet 127.0.0.1 80
```

### "Permission denied" on ports < 1024

Use a higher port or run with elevated privileges:

```
sudo ./arctic-proxy 0.0.0.0:80 127.0.0.1:8080
```

### High error count

- Check upstream server health
- Verify network connectivity
- Increase timeout values
- Review system resource limits (file descriptors, memory)

## 📈 Benchmarking

Test Arctic Proxy with common load testing tools:

```
# wrk
wrk -t12 -c1000 -d30s http://localhost:8080/

# Apache Bench
ab -n 100000 -c 1000 http://localhost:8080/

# hey
hey -n 100000 -c 1000 http://localhost:8080/
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Tokio](https://tokio.rs/) async runtime
- Socket operations powered by [socket2](https://github.com/rust-lang/socket2)
- Inspired by high-performance proxy designs from HAProxy and NGINX

## 📧 Contact

- **Issues**: [GitHub Issues](https://github.com/s-b-repo/arctic-proxy/issues)
- **Discussions**: [GitHub Discussions](https://github.com/s-b-repo/arctic-proxy/discussions)

---

**Made with ❤️ and Rust** 🦀
