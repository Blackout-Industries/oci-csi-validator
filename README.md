# OCI CSI VolumeAttachment Validator

Finds and deletes orphaned K8s VolumeAttachments in OCI/OKE clusters.

## What it does

After node replacements, VolumeAttachments can point to dead nodes. This finds them and optionally deletes them.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Config

Create `.env`:
```bash
OCI_COMPARTMENT_ID=ocid1.compartment.oc1..aaaaaaaa...
K8S_CONTEXT=your-context-name
```

## Usage

```bash
# Scan (dry-run)
python oci_csi_validator.py

# Delete orphans
python oci_csi_validator.py --delete

# JSON output
python oci_csi_validator.py --output json

# Skip confirmation
python oci_csi_validator.py --delete --yes
```

## Output

Groups orphaned attachments by missing node with truncated IDs:

```
╔══════════════════════════════════════════════════════╗
║        OCI CSI VolumeAttachment Validator            ║
╚══════════════════════════════════════════════════════╝

Compartment             ocid1.compar...px53nw6bhtmq
Kubernetes Context      context-cyocvdj7kvq
Total VolumeAttachments 52
Active Nodes            33
Healthy Attachments     50
Orphaned Attachments    2 ⚠️

╭──────────────────────────────────────────────────────╮
│ Missing Node: 10.1.193.86 (2 orphaned attachments)   │
╰──────────────────────────────────────────────────────╯

  Attachment ID         Volume ID             Age
  csi-4e10c7de...       csi-e4215b46...    169h14m
  csi-68006dbb...       csi-d99315de...    169h14m
```

## How it works

1. Queries K8s for all VolumeAttachments
2. Queries K8s for all active nodes
3. Finds attachments pointing to non-existent nodes
4. Groups by node, shows truncated IDs
5. Optionally deletes (with re-validation + confirmation)

## Exit codes

- `0` - Success
- `1` - Orphans found (scan mode) or deletion failed
- `2` - Config error
- `3` - K8s API error
- `4` - Other error

## Tests

```bash
pytest tests/ -v
```

## Requirements

- Python 3.9+
- kubectl access to target cluster
- RBAC: list/delete VolumeAttachments, list Nodes

## RBAC

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: volume-attachment-cleaner
rules:
- apiGroups: ["storage.k8s.io"]
  resources: ["volumeattachments"]
  verbs: ["get", "list", "delete"]
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list"]
```

## Cron

```bash
0 * * * * cd /path/to/validator && .venv/bin/python oci_csi_validator.py --delete --yes >> /var/log/oci-csi.log 2>&1
```

## Safety

- Dry-run by default (requires `--delete`)
- Re-validates nodes before deletion
- Confirmation for >5 deletions
- Skips if node reappears
- Full audit log
