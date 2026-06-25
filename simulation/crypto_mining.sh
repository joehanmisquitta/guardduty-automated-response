#!/bin/bash
# simulation/crypto_mining.sh
#
# Triggers: CryptoCurrency:EC2/BitcoinTool.B
#
# Run this FROM the target EC2 instance.
# GuardDuty detects DNS queries and outbound connections to known
# cryptocurrency mining pool domains. It does NOT require actual
# mining software — the network activity alone triggers the finding.
#
# Usage:
#   chmod +x crypto_mining.sh
#   ./crypto_mining.sh
#
# Note: This only simulates the network behaviour GuardDuty watches.
# No actual mining occurs. Free tier EC2 can't mine anyway.

set -euo pipefail

# Known mining pool domains that appear in GuardDuty's threat intel lists
# These are real mining pool domains — connecting to them simulates the finding
MINING_POOLS=(
  "pool.minexmr.com"
  "xmr.pool.minergate.com"
  "mine.moneropool.com"
  "pool.supportxmr.com"
  "xmrpool.eu"
)

# Mining pool ports commonly used
MINING_PORTS=("3333" "4444" "8080" "14444")

echo "[*] Starting cryptocurrency mining simulation"
echo "[*] Making DNS queries and connection attempts to known mining pools"
echo "[*] Expected finding: CryptoCurrency:EC2/BitcoinTool.B"
echo ""

for POOL in "${MINING_POOLS[@]}"; do
  echo "[*] DNS query to $POOL ..."
  nslookup "$POOL" 2>/dev/null || true

  echo "[*] Connection attempt to $POOL:3333 ..."
  # Use nc (netcat) with a short timeout — connection attempt is enough
  timeout 3 nc -zv "$POOL" 3333 2>/dev/null || true

  sleep 1
done

# Also try HTTP to mining pool endpoints
echo ""
echo "[*] HTTP connection attempts to mining pools ..."
curl --connect-timeout 3 --max-time 5 "http://pool.minexmr.com" 2>/dev/null || true
curl --connect-timeout 3 --max-time 5 "http://xmr.pool.minergate.com" 2>/dev/null || true

echo ""
echo "[*] Crypto mining simulation complete"
echo "[*] Check GuardDuty findings in 5-15 minutes"
echo "[*] Or generate a sample finding immediately:"
echo "    aws guardduty create-sample-findings \\"
echo "      --detector-id <DETECTOR_ID> \\"
echo "      --finding-types 'CryptoCurrency:EC2/BitcoinTool.B'"
