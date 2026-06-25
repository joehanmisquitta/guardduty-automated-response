# GuardDuty Automated EC2 Isolation

Automated threat detection and response pipeline on AWS. When GuardDuty flags a compromised EC2 instance, the pipeline isolates it within seconds, no human intervention required.

---

## Problem Statement

A fast-growing SaaS company has no automated response capability for EC2 threats. When GuardDuty flags an instance for SSH brute force, malicious IP communication, or cryptomining activity, the security team has to manually investigate and isolate, a process that takes 30–45 minutes and relies on someone being available. The window between detection and containment is where attackers do the most damage.

---

## Architecture

```
[Attacker EC2]  ──attack──►  [Target EC2]
                                   │
                          VPC Flow Logs / DNS
                                   │
                             [GuardDuty] ── finding ──►  [S3 Findings Bucket]
                                   │
                           [EventBridge Rule]
                          (filters by finding type
                           and severity ≥ MEDIUM)
                                   │
                           [Lambda Function]
                          ┌────────┴────────┐
                          │  isolate_instance │
                          │  1. parse finding │
                          │  2. swap SG       │
                          │  3. tag instance  │
                          │  4. publish alert │
                          └────────┬────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
              [Quarantine SG]  [SNS Alert]  [CloudWatch Logs]
              (zero rules —    (email with  (JSON structured
               no in/out)       full context) audit trail)
```

### Finding Types Handled

| GuardDuty Finding | Simulated By | Severity |
|---|---|---|
| `UnauthorizedAccess:EC2/SSHBruteForce` | Hydra from attacker EC2 | Medium |
| `UnauthorizedAccess:EC2/MaliciousIPCaller` | curl to threat intel IPs | High |
| `CryptoCurrency:EC2/BitcoinTool.B` | DNS queries to mining pools | High |

---

## What Gets Built

| Resource | Purpose |
|---|---|
| GuardDuty Detector | Monitors VPC Flow Logs, DNS logs, EC2 activity |
| EventBridge Rule | Filters findings by type and severity ≥ Medium |
| Lambda Function | Core response logic — isolates instance in < 2 seconds |
| Quarantine Security Group | Zero inbound/outbound rules — complete network isolation |
| SNS Topic + Email | Enriched alert with instance details and next steps |
| CloudWatch Dashboard | Live view of findings, Lambda execution, isolation count |
| S3 Findings Bucket | Long-term encrypted findings export for audit trail |
| VPC + Flow Logs | Network visibility required for GuardDuty network findings |
| 2 EC2 Instances | Target (victim) and attacker for simulation |

---

## Prerequisites

- AWS free tier account
- Terraform >= 1.5.0
- AWS CLI configured (`aws configure`)
- An SSH key pair generated locally

---

## Deployment

```bash
# 1. Clone the repo
git clone https://github.com/your-username/guardduty-automated-response
cd guardduty-automated-response

# 2. Generate an SSH key pair for the lab EC2 instances
ssh-keygen -t ed25519 -f lab-key -C "guardduty-lab"
# This creates lab-key (private) and lab-key.pub (public)
# lab-key is gitignored — never commit it

# 3. Set your variables
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — set your email address at minimum

# 4. Init and apply
terraform init
terraform plan
terraform apply

# 5. Note the outputs — you'll need the detector ID and instance IDs
# Check your email and confirm the SNS subscription before testing
```

---

## Testing the Pipeline

### Step 1 - Verify with sample findings (do this first)

```bash
# Replace <DETECTOR_ID> with the output from terraform apply
aws guardduty create-sample-findings \
  --detector-id <DETECTOR_ID> \
  --finding-types "UnauthorizedAccess:EC2/SSHBruteForce" \
  --region ap-south-1
```

This fires a sample finding that goes through the full pipeline — EventBridge → Lambda → quarantine SG swap → SNS email. Verify each step before running real simulations.

### Step 2 - SSH brute force simulation

```bash
# SSH into the attacker instance
ssh -i lab-key ec2-user@<ATTACKER_PUBLIC_IP>

# Run the brute force script against the target
chmod +x simulation/ssh_bruteforce.sh
./simulation/ssh_bruteforce.sh <TARGET_PRIVATE_IP>
```

### Step 3 - Malicious IP simulation

```bash
# SSH into the target instance
ssh -i lab-key ec2-user@<TARGET_PUBLIC_IP>

chmod +x simulation/malicious_ip.sh
./simulation/malicious_ip.sh
```

### Step 4 - Crypto mining simulation

```bash
# Still on the target instance
chmod +x simulation/crypto_mining.sh
./simulation/crypto_mining.sh
```

### Step 5 - Verify isolation

```bash
# Check that the target's SG was swapped to the quarantine SG
aws ec2 describe-instances \
  --instance-ids <TARGET_INSTANCE_ID> \
  --query 'Reservations[].Instances[].SecurityGroups' \
  --region ap-south-1

# Check the quarantine tags on the instance
aws ec2 describe-tags \
  --filters "Name=resource-id,Values=<TARGET_INSTANCE_ID>" \
  --region ap-south-1
```

---

## Response Time

| Stage | Time |
|---|---|
| GuardDuty detects finding (sample) | Immediate |
| GuardDuty detects finding (real) | 5–15 minutes |
| EventBridge routes to Lambda | < 1 second |
| Lambda isolates instance | ~2 seconds |
| SNS email delivered | ~30 seconds |
| **Total: detection to isolation** | **< 5 seconds (sample) / ~15 min (real)** |

---

## Cleanup

```bash
cd terraform
terraform destroy
```

Note: GuardDuty charges ~$1–2/month per account even on free tier after the 30-day trial. Disable the detector after the lab if you're not actively using it.

---

## Skills Demonstrated

- AWS GuardDuty - threat detection configuration, finding types, severity tuning
- AWS Lambda - event-driven response automation, Python boto3, structured logging
- AWS EventBridge - event pattern matching, rule filtering, dead letter queues
- AWS EC2 - security group management, instance tagging, VPC Flow Logs
- AWS SNS - topic policy, email subscription, programmatic publishing
- Infrastructure as Code - Terraform, modular resource organisation
- Incident Response - automated containment, audit trail, post-incident tagging
- MITRE ATT&CK mapping - T1110 (Brute Force), T1071 (C2), T1496 (Resource Hijacking)
