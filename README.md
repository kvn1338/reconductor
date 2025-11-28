# reconductor

> **Orchestrate your reconnaissance like a symphony** 🎵

Fast, parallel network scanning with nmap and nuclei. Automatically resumes, queues and avoids losing progress. This started as a simple shell script to streamline scanning large networks in an efficient manner and grew into this over time...

## Features

- 🚀 **Parallel Execution**: Run multiple nmap and nuclei scans concurrently
- 💾 **Automatic State Management**: Resume interrupted scans from where they left off
- 📦 **Smart Subnet Splitting**: Automatically splits large subnets into /24 chunks for better parallelization
- 🎯 **Optimized nmap Workflow**: Fast host discovery → Quick port discovery → Detailed service scan
- 🔄 **Queue-Based Architecture**: Efficient task distribution across workers
- 📊 **Progress Tracking**: Real-time visibility into scan progress

## Quick Start

### Requirements

- Python 3.7+
- nmap 7.0+
- nuclei (optional, for vulnerability scanning)
- Root/sudo access (for SYN scans)

### Installation

```bash
# Install Python dependencies (for testing)
pip install -r requirements.txt

# Or install manually
pip install pytest pytest-cov pytest-asyncio
```

### Basic Usage

```bash
# Create targets file
cat > targets.txt << EOF
192.168.1.0/24
10.0.0.0/16
EOF

# Run scan
sudo ./reconductor.py targets.txt

# Check results
ls -la scan_results/
```

### Common Scenarios

```bash
# Fast scan with 2 parallel workers
sudo ./reconductor.py --max-nmap 2 --max-nuclei 2 targets.txt

# Host discovery only (fastest - just find what's alive)
sudo ./reconductor.py --hosts-only targets.txt

# Resume interrupted scan
sudo ./reconductor.py --resume targets.txt

# Custom output directory
sudo ./reconductor.py --output-dir my_scan targets.txt

# Fast scan with fewer ports (576 = ~90% coverage)
sudo ./reconductor.py --top-ports 576 targets.txt
```

## Scan Modes

**Full Scan (default)**: Host discovery → Port scanning → Service detection → Nuclei vulnerability scan

**Ports Only**: `--ports-only` - Skip service enumeration, just find open ports

**Hosts Only**: `--hosts-only` - Just discover live hosts (fastest)

## Output Structure

```
scan_results/
├── targets_state.json              # State file for resumability
└── 192_168_1_0-24/                # Per-target directory
    ├── ips.txt                    # Live hosts
    ├── hosts.nmap                 # Host discovery results
    ├── open-ports.xml             # Port scan results
    ├── service_scan.nmap          # Service/version detection
    └── nuclei/                    # Vulnerability findings
        └── output.json
```

## Key Options

### Performance

```bash
--max-nmap N          # Number of parallel nmap workers (default: 1)
--max-nuclei N        # Number of parallel nuclei workers (default: 1)
--top-ports N         # Number of ports to scan (default: 1000)
--min-rate N          # Min packets/sec for port scans (default: 500)
--host-min-rate N     # Min packets/sec for host discovery (default: 1000)
```

### Timeouts

```bash
--timeout N           # Nmap scan timeout in minutes (default: 60)
--host-timeout N      # Host discovery timeout in minutes (default: 30)
```

### Scan Control

```bash
--hosts-only          # Only perform host discovery
--ports-only          # Stop after port scanning (no service detection)
--version-intensity N # nmap version detection intensity 0-9 (default: 2)
--no-split            # Don't split large subnets into /24s
--resume              # Resume from previous state
```

## Targets File Format

```
# Single IPs
192.168.1.1
10.0.0.1

# CIDR subnets (will be split into /24s automatically)
10.0.0.0/16
192.168.0.0/20

# /24 subnets (used as-is)
172.16.1.0/24

# Comments are supported
# 192.168.2.0/24  <- this line is ignored
```

## Architecture

### High-Level Design

```
Input Targets → Split into /24s → Queue-based orchestrator
                                          ↓
                    ┌─────────────────────┴──────────────────────┐
                    ↓                                             ↓
              Nmap Workers                                  Nuclei Workers
         (parallel host/port/service)                    (parallel vuln scan)
                    ↓                                             ↓
              Per-target output                          Per-target output
```

### Scan Flow

1. **Host Discovery** - Find live hosts (fast)
2. **Port Discovery** - Identify open ports (no banners)
3. **Service Scan** - Deep service/version detection (only on open ports)
4. **Nuclei Scan** - Vulnerability scanning (after service scan completes)

Each stage is tracked in state file for resumability.

## Performance Tips

### Fast Scanning

```bash
# Aggressive scanning for speed
sudo ./reconductor.py \
  --max-nmap 3 \
  --max-nuclei 2 \
  --top-ports 576 \
  --min-rate 1000 \
  targets.txt
```

### Accurate Scanning

```bash
# Conservative scanning for accuracy
sudo ./reconductor.py \
  --top-ports 5000 \
  --version-intensity 7 \
  --timeout 120 \
  --min-rate 100 \
  targets.txt
```

### Large Networks

```bash
# Optimized for /16 or larger
sudo ./reconductor.py \
  --max-nmap 3 \
  --timeout 120 \
  --host-timeout 60 \
  large_targets.txt
```

## Troubleshooting

**Scan too slow?** Increase `--max-nmap`, reduce `--top-ports`, or increase `--min-rate`

**Timeouts?** Increase `--timeout` and `--host-timeout` values

**Resume not working?** Verify `--output-dir` matches previous scan and state file exists

**Need root?** Yes, for SYN scans (`-sS`). Without sudo, falls back to slower TCP connect scans

## Monitoring Progress

```bash
# Watch state file updates
watch -n 5 'cat scan_results/*_state.json | jq .metadata'

# Check stage distribution
cat scan_results/*_state.json | \
  jq -r '.targets | to_entries[] | .value.stage' | sort | uniq -c

# Find completed targets
cat scan_results/*_state.json | \
  jq -r '.targets | to_entries[] | select(.value.stage == "complete") | .key'
```

## Testing

```bash
# Install test dependencies first
pip install -r requirements.txt

# Run test suite
pytest

# Or with unittest (no dependencies needed)
python3 -m unittest discover tests/

# With coverage
pytest --cov=. --cov-report=term-missing
```

## Contributing

Improvements welcome! Areas of interest:

- IPv6 support
- Custom nmap scripts
- Distributed scanning
- Web dashboard for progress monitoring

## License

Use responsibly and only on networks you have permission to scan.

## References

- [Nmap Performance Guide](https://nmap.org/book/man-performance.html)
- [Nuclei Documentation](https://nuclei.projectdiscovery.io/)
