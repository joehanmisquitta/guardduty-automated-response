#!/bin/bash
# simulation/malicious_ip.sh
#
# Triggers: UnauthorizedAccess:EC2/MaliciousIPCaller
#
# Run this FROM the target EC2 instance.
# GuardDuty maintains a threat intelligence list of known malicious IPs.
# Outbound connections to those IPs trigger this finding.
#
# Usage:
#   chmod +x malicious_ip.sh
#   ./malicious_ip.sh
#
# Note: AWS provides a test IP range specifically for GuardDuty simulation.
# The 198.51.100.0/24 range (TEST-NET-2, RFC 5737) is used by GuardDuty's
# own threat intel simulation. Check AWS docs for the current test endpoint.

set -euo pipefail

# GuardDuty threat intel test IPs
# These are documented AWS test addresses that trigger findings
MALICIOUS_IPS=(
  "198.51.100.1"
  "198.51.100.2"
  "198.51.100.3"
)

echo "[*] Starting malicious IP simulation"
echo "[*] Making outbound connections to GuardDuty threat intel IPs"
echo "[*] Expected finding: UnauthorizedAccess:EC2/MaliciousIPCaller"
echo ""

for IP in "${MALICIOUS_IPS[@]}"; do
  echo "[*] Connecting to $IP ..."
  # curl with short timeout — connection attempt is enough to trigger finding
  curl --connect-timeout 3 --max-time 5 "http://$IP" 2>/dev/null || true
  # Also try DNS-level connection
  nslookup "$IP" 2>/dev/null || true
  echo "[*] Connection attempt to $IP complete"
  sleep 2
done

echo ""
echo "[*] Malicious IP simulation complete"
echo "[*] Check GuardDuty findings in 5-15 minutes"
echo "[*] Or generate a sample finding immediately:"
echo "    aws guardduty create-sample-findings \\"
echo "      --detector-id <DETECTOR_ID> \\"
echo "      --finding-types 'UnauthorizedAccess:EC2/MaliciousIPCaller.Custom'"
