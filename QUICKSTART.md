# reconductor Quick Start Guide

Get scanning in under 5 minutes!

## Prerequisites

```bash
# Check you have the required tools
which nmap
which nuclei  # optional but recommended
which python3

# Check Python version (need 3.7+)
python3 --version
```

## Installation

```bash
# Navigate to reconductor directory
cd /path/to/reconductor

# Make scripts executable
chmod +x reconductor.py run.sh

# Verify it works
./reconductor.py --help
```

## Your First Scan

### Step 1: Create a targets file

```bash
# Create a file with your targets
cat > my_targets.txt << EOF
192.168.1.0/24
10.0.0.0/24
EOF
```

### Step 2: Run the scan

```bash
# Basic scan (requires root for SYN scans)
sudo ./reconductor.py my_targets.txt

# Or use the wrapper script
sudo ./run.sh my_targets.txt
```

### Step 3: Check results

```bash
# Results are in scan_results/ by default
ls -la scan_results/

# View state file
cat scan_results/my_targets_state.json | jq .

# View discovered hosts for a subnet
cat scan_results/192_168_1_0-24/ips.txt

# View service scan results
cat scan_results/192_168_1_0-24/service_scan.nmap
```

## Common Use Cases

### Fast Scan (90% port coverage)

```bash
sudo ./reconductor.py --top-ports 576 my_targets.txt
```

### Parallel Scanning (faster)

```bash
# Run 2 nmap workers and 2 nuclei workers
sudo ./reconductor.py --max-nmap 2 --max-nuclei 2 my_targets.txt
```

### Scan Mode Options

```bash
# Host discovery only (fastest - just find what's alive)
sudo ./reconductor.py --hosts-only my_targets.txt

# Host discovery + port scanning (no service enumeration)
sudo ./reconductor.py --ports-only --top-ports 100 my_targets.txt

# Full scan with all stages (default)
sudo ./reconductor.py my_targets.txt
```

### Resume Interrupted Scan

```bash
# If scan was interrupted (Ctrl+C, crash, etc.)
sudo ./reconductor.py --resume my_targets.txt

# Make sure to use the same --output-dir if you specified one
sudo ./reconductor.py --resume --output-dir my_results my_targets.txt
```

### Scan Large Network

```bash
# For /16 or larger subnets
# Automatically splits into /24s, higher timeout, parallel workers
sudo ./reconductor.py \
  --max-nmap 3 \
  --max-nuclei 2 \
  --timeout 120 \
  --host-timeout 60 \
  large_network.txt
```

### Conservative Scan (avoid rate limiting)

```bash
sudo ./reconductor.py \
  --min-rate 100 \
  --host-min-rate 200 \
  --max-nmap 1 \
  sensitive_targets.txt
```

## Understanding the Output

### Directory Structure

```
scan_results/
├── my_targets_state.json          # Resume state (important!)
└── 192_168_1_0-24/                # One directory per /24 subnet
    ├── hosts.nmap                 # Host discovery results
    ├── hosts.gnmap               
    ├── hosts.xml                  
    ├── ips.txt                    # List of live hosts
    ├── open-ports.xml             # Port scan results
    ├── service_scan.nmap          # Service/version detection
    ├── service_scan.gnmap
    ├── service_scan.xml
    └── nuclei/                    # Vulnerability scan results
        ├── output.json
        └── *.md
```

### Key Files

- **ips.txt**: List of live hosts (one per line)
- **service_scan.nmap**: Most important - services and versions
- **nuclei/**: Vulnerability findings
- **state.json**: Tracks progress, enables resume

## Monitoring Progress

### Watch the State File

```bash
# In another terminal
watch -n 5 'cat scan_results/my_targets_state.json | jq .metadata'
```

### Check Stage Distribution

```bash
cat scan_results/my_targets_state.json | \
  jq -r '.targets | to_entries[] | .value.stage' | \
  sort | uniq -c
```

### Find Completed Targets

```bash
cat scan_results/my_targets_state.json | \
  jq -r '.targets | to_entries[] | select(.value.stage == "complete") | .key'
```

### Find Failed Targets

```bash
cat scan_results/my_targets_state.json | \
  jq -r '.targets | to_entries[] | select(.value.stage == "failed") | "\(.key): \(.value.error)"'
```

## Troubleshooting

### Problem: "Not running as root"

**Solution**: Use sudo

```bash
sudo ./reconductor.py my_targets.txt
```

### Problem: Scan is too slow

**Solutions**:

```bash
# 1. Increase parallelization
sudo ./reconductor.py --max-nmap 3 my_targets.txt

# 2. Scan fewer ports
sudo ./reconductor.py --top-ports 100 my_targets.txt

# 3. Increase packet rate
sudo ./reconductor.py --min-rate 1000 my_targets.txt

# 4. Disable version detection (fast but less info)
sudo ./reconductor.py --version-intensity 0 my_targets.txt
```

### Problem: Timeouts

**Solution**: Increase timeout values

```bash
sudo ./reconductor.py --timeout 180 --host-timeout 90 my_targets.txt
```

### Problem: Want to restart from scratch

**Solution**: Delete state file and output directory

```bash
rm -rf scan_results/
sudo ./reconductor.py my_targets.txt
```

### Problem: Scan interrupted, want to continue

**Solution**: Use --resume flag

```bash
sudo ./reconductor.py --resume my_targets.txt
```

## Tips & Tricks

### 1. Quick Host Discovery Sweep

```bash
# Fast sweep to find live hosts only (no port scanning)
sudo ./reconductor.py --hosts-only --max-nmap 3 large_network.txt

# Results in: scan_results/<target>/ips.txt
```

### 2. Organize Scans by Date

```bash
# Keep scans organized by date
sudo ./reconductor.py --output-dir scans/$(date +%Y-%m-%d) my_targets.txt
```

### 3. Scan Specific Subnets from Large List

```bash
# Only scan first 3 targets
head -3 large_targets.txt > small_batch.txt
sudo ./reconductor.py small_batch.txt
```

### 4. Combine Multiple Target Lists

```bash
cat list1.txt list2.txt list3.txt > combined.txt
sort -u combined.txt > unique_targets.txt
sudo ./reconductor.py unique_targets.txt
```

### 5. Extract All Live Hosts

```bash
# From all scanned subnets
cat scan_results/*/ips.txt | sort -u > all_live_hosts.txt
```

### 5. Find Hosts with Specific Port Open

```bash
# Find all hosts with port 22 open
grep -r "22/open" scan_results/*/service_scan.gnmap | \
  cut -d' ' -f2 | sort -u
```

### 6. Export to CSV

```bash
# Simple CSV of targets and status
echo "target,stage,live_hosts,open_ports" > scan_summary.csv
cat scan_results/my_targets_state.json | \
  jq -r '.targets | to_entries[] | 
    "\(.key),\(.value.stage),\(.value.live_hosts | length),\(.value.open_ports)"' \
  >> scan_summary.csv
```

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Explore the modular code structure
- Customize nmap commands in `config.py`
- Adjust timeouts and rates for your network
- Integrate with your analysis tools

## Example Workflow

```bash
# 1. Prepare targets
echo "10.0.0.0/16" > corporate_network.txt

# 2. Start scan with good defaults
sudo ./reconductor.py \
  --max-nmap 2 \
  --max-nuclei 2 \
  --output-dir corp_scan_$(date +%Y%m%d) \
  corporate_network.txt

# 3. Monitor in another terminal
watch -n 10 'ls -lh corp_scan_*/*/service_scan.nmap 2>/dev/null | wc -l'

# 4. After scan completes, analyze
cd corp_scan_*/
grep -h "open" */service_scan.nmap | sort | uniq -c | sort -rn

# 5. Extract interesting findings
cat */nuclei/*.json | jq -r '.info.severity' | sort | uniq -c
```

Happy scanning! 🎯