# reconductor

> **Orchestrate your reconnaissance like a symphony** 🎵

Fast, parallel network scanning with nmap and nuclei. Automatically resumes, intelligently queues, never loses progress.

## Features

- 🚀 **Parallel Execution**: Run multiple nmap and nuclei scans concurrently
- 💾 **Automatic State Management**: Resume interrupted scans from where they left off
- 📦 **Smart Subnet Splitting**: Automatically splits large subnets into /24 chunks for better parallelization
- 🎯 **Optimized nmap Workflow**: 
  1. Fast host discovery
  2. Quick port discovery (no banners)
  3. Detailed service scan only on open ports
- 🔄 **Queue-Based Architecture**: Efficient task distribution across workers
- 📊 **Progress Tracking**: Real-time visibility into scan progress

## Architecture

### Modular Design

```
reconductor/
├── reconductor.py    # Main entry point and CLI
├── config.py      # Configuration and command templates
├── state.py       # State management and persistence
├── scanner.py     # Worker classes and orchestration
└── utils.py       # Utility functions (IP validation, parsing, etc.)
```

### Queue-Based Workflow

```
Input Targets
     ↓
Split into /24 subnets
     ↓
┌────────────────────────────────────────┐
│         Scan Orchestrator              │
│  (Manages queues and worker pools)     │
└────────────────────────────────────────┘
     ↓                    ↓
┌─────────────┐    ┌──────────────┐
│ Nmap Queue  │    │ Nuclei Queue │
└─────────────┘    └──────────────┘
     ↓                    ↓
Multiple Workers    Multiple Workers
(max-nmap)          (max-nuclei)
```

### Scan Stages

Each target progresses through these stages:

1. **PENDING** → Initial state
2. **HOST_DISCOVERY** → nmap host discovery scan
3. **HOST_DISCOVERY_COMPLETE** → Live hosts identified
4. **PORT_DISCOVERY** → Fast port scan (no version detection)
5. **PORT_DISCOVERY_COMPLETE** → Open ports identified
6. **SERVICE_SCAN** → Detailed service/version scan on open ports
7. **SERVICE_SCAN_COMPLETE** → Services identified
8. **NUCLEI_SCAN** → Vulnerability scanning (runs in parallel with service scan)
9. **COMPLETE** → All scans finished

Nuclei scans run in parallel with port/service discovery after host discovery completes.

## Installation

### Requirements

- Python 3.7+
- nmap 7.0+
- nuclei (optional, for vulnerability scanning)
- Root/sudo access (for SYN scans)

### Setup

```bash
cd reconductor
chmod +x reconductor.py

# Verify dependencies
which nmap
which nuclei
```

## Usage

### Basic Usage

```bash
# Simple scan with defaults
sudo ./reconductor.py targets.txt

# Specify output directory
sudo ./reconductor.py --output-dir results targets.txt
```

### Parallelization

```bash
# Run 2 nmap workers and 2 nuclei workers concurrently
sudo ./reconductor.py --max-nmap 2 --max-nuclei 2 targets.txt

# Higher performance mode
sudo ./reconductor.py --max-nmap 4 --max-nuclei 3 targets.txt
```

### Scan Mode Options

```bash
# Host discovery only (fastest - just find what's alive)
sudo ./reconductor.py --hosts-only targets.txt

# Host discovery + port scanning only (skip service enumeration)
sudo ./reconductor.py --ports-only --top-ports 100 targets.txt

# Full scan with all stages (default)
sudo ./reconductor.py targets.txt
```

### Customizing Scans

```bash
# Fast scan: 576 ports (~90% coverage)
sudo ./reconductor.py --top-ports 576 targets.txt

# Increase scan speed (more aggressive)
sudo ./reconductor.py --min-rate 1000 --host-min-rate 2000 targets.txt

# Adjust timeouts (in minutes)
sudo ./reconductor.py --timeout 120 --host-timeout 60 targets.txt

# More aggressive version detection
sudo ./reconductor.py --version-intensity 5 targets.txt
```

### Resume Interrupted Scans

```bash
# Resume from previous state
sudo ./reconductor.py --resume --output-dir results targets.txt

# State is automatically saved, just re-run with --resume
```

### Advanced Options

```bash
# Don't split large subnets (not recommended)
sudo ./reconductor.py --no-split targets.txt

# Combine options
sudo ./reconductor.py \
  --max-nmap 3 \
  --max-nuclei 2 \
  --top-ports 1000 \
  --timeout 90 \
  --min-rate 750 \
  --output-dir my_scan \
  targets.txt
```

## Targets File Format

Create a text file with one target per line:

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

## Output Structure

```
scan_results/
├── targets_state.json              # State file for resumability
├── 10_0_0_0-24/                   # Per-target directory
│   ├── hosts.nmap                 # Host discovery results
│   ├── hosts.gnmap
│   ├── hosts.xml
│   ├── ips.txt                    # Live hosts list
│   ├── open-ports.xml             # Port discovery results
│   ├── service_scan.nmap          # Service scan results
│   ├── service_scan.gnmap
│   ├── service_scan.xml
│   └── nuclei/                    # Nuclei results
│       ├── output.json
│       └── *.md                   # Markdown reports
├── 10_0_1_0-24/
│   └── ...
└── ...
```

## State File

The state file (`*_state.json`) tracks:
- Current stage of each target
- Live hosts discovered
- Open ports found
- Timestamps
- Error messages

This enables:
- Resuming interrupted scans
- Progress tracking
- Audit trail

Example state:

```json
{
  "metadata": {
    "created_at": "2024-11-27T10:00:00.123456",
    "last_updated": "2024-11-27T11:30:00.654321",
    "version": "1.0"
  },
  "targets": {
    "10.0.0.0/24": {
      "target": "10.0.0.0/24",
      "stage": "service_scan_complete",
      "directory": "scan_results/10_0_0_0-24",
      "live_hosts": ["10.0.0.1", "10.0.0.10", "10.0.0.50"],
      "open_ports": "22,80,443",
      "started_at": "2024-11-27T10:00:00.123456",
      "completed_at": "2024-11-27T11:30:00.654321",
      "error": null
    }
  }
}
```

## Performance Tips

### Optimizing for Speed

1. **Increase parallelization**: `--max-nmap 3 --max-nuclei 2`
2. **Reduce ports scanned**: `--top-ports 576` (90% coverage)
3. **Increase packet rate**: `--min-rate 1000`
4. **Lower version intensity**: `--version-intensity 0` (disables version detection)

### Optimizing for Accuracy

1. **More ports**: `--top-ports 5000`
2. **Higher version intensity**: `--version-intensity 7`
3. **Longer timeouts**: `--timeout 120`
4. **Conservative rate**: `--min-rate 100` (less likely to be rate-limited)

### Resource Considerations

- **CPU**: Each nmap worker uses 1-2 cores
- **Memory**: ~100-500MB per nmap worker
- **Network**: Depends on `--min-rate` setting
- **Disk**: ~1-10MB per /24 subnet scanned

## Troubleshooting

### "Not running as root" Warning

SYN scans (`-sS`) require root. Without root, nmap falls back to TCP connect scans which are:
- Slower
- More detectable
- Less reliable

Solution: Run with `sudo`

### Scan Hangs or Times Out

1. Increase timeouts: `--timeout 120`
2. Reduce rate: `--min-rate 100`
3. Check network connectivity
4. Check firewall rules

### "Command timed out" Errors

This is normal for large subnets or slow networks. The scan continues with other targets. To adjust:

```bash
# Increase timeout for large networks
sudo ./reconductor.py --timeout 180 --host-timeout 90 targets.txt
```

### Resume Not Working

Check that:
1. `--output-dir` matches previous scan
2. State file exists: `scan_results/*_state.json`
3. File permissions are correct

### High Memory Usage

Reduce parallelization:

```bash
sudo ./reconductor.py --max-nmap 1 --max-nuclei 1 targets.txt
```

## Nmap Command Details

### 1. Host Discovery
```bash
nmap -vvv -n -sn -PE -PM -PP \
  --min-hostgroup 512 \
  --min-rate 1000 \
  --max-retries 3 \
  --max-rtt-timeout 200ms \
  -oA hosts TARGET
```

### 2. Port Discovery (Fast)
```bash
nmap -n -Pn -sS \
  --min-rate 500 \
  --max-retries 3 \
  --top-ports 1000 \
  -oX open-ports.xml \
  -iL ips.txt
```

### 3. Service Scan (Detailed)
```bash
nmap -n -Pn -sV \
  --version-intensity 2 \
  -iL ips.txt \
  -p <discovered-ports> \
  -oA service_scan
```

### 4. Nuclei Scan
```bash
nuclei \
  -list ips.txt \
  -markdown-export nuclei/ \
  -json-export nuclei/output.json
```

## Contributing

Improvements welcome! Key areas:

- IPv6 support
- Custom nmap script support
- Web dashboard for progress
- Distributed scanning across multiple machines
- Integration with other tools (masscan, etc.)

## License

Use responsibly and only on networks you have permission to scan.

## References

- [Nmap Port Selection](https://nmap.org/book/performance-port-selection.html)
- [Nmap Performance](https://nmap.org/book/man-performance.html)
- [Nuclei Documentation](https://nuclei.projectdiscovery.io/)
