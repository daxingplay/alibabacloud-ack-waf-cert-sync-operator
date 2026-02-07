# Alibaba Cloud WAF Certificate Sync Operator

An event-driven Kubernetes operator that automatically synchronizes TLS certificates from `cert-manager` (or any K8s Secret) to **Alibaba Cloud WAF 2.0/3.0** and **Certificate Management Service (CAS)**.

## 🚀 Overview

In a typical ACK (Alibaba Cloud Container Service) setup using a **Layer-4 CLB** with **WAF enabled**, SSL termination happens at the WAF layer. When `cert-manager` renews a certificate in Kubernetes, the WAF is unaware of the change.

This project bridges that gap. It uses `shell-operator` to:

1. **Watch** for updates to a specific Kubernetes TLS Secret.
2. **Identify** the certificate using its SHA-1 fingerprint to prevent redundant uploads.
3. **Upload** the new certificate to Alibaba Cloud CAS with a custom date-based name.
4. **Update** the WAF Cloud Resource configuration to use the new certificate ID.

## ✨ Features

* **Zero Credentials:** Uses **RRSA** (RAM Roles for Service Accounts) for secure, token-based authentication (no AccessKeys stored in K8s).
* **Idempotent:** Matches certificates by cryptographic fingerprint. It won't upload the same cert twice.
* **Immutable:** The script and dependencies (`aliyun-cli`, `jq`) are baked into a single Docker image.
* **Configurable:** All parameters (WAF Instance ID, Secret Name, TLS versions) are managed via environment variables.

## Image

Pre-built images are published to **GitHub Container Registry (GHCR)** via [GitHub Actions](.github/workflows/build-and-push.yml).

---

## 🛠 Prerequisites

1. **ACK Cluster:** Ensure RRSA is enabled in your Alibaba Cloud ACK cluster.
2. **ack-pod-identity-webhook** installed in your cluster.
3. **cert-manager:** Successfully issuing certificates to a Kubernetes Secret.
4. **RAM Role:** A role configured for RRSA with the following policy:

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "yundun-cert:ListUserCertificateOrder",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "yundun-waf:ModifyCloudResource",
        "yundun-waf:CreateCerts"
      ],
      "Resource": "*"
    }
  ]
}

```

---

## 📦 Installation

### 1. Configure the ServiceAccount and Permission

The operator needs permission to `watch` and `get` the specific Secret it is protecting. We use a **Role** (instead of a ClusterRole) to limit access to a single namespace.

```yaml
# rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cert-sync-sa
  namespace: your_namespace
  annotations:
    # LINK TO ALIBABA RAM ROLE (RRSA)
    pod-identity.alibabacloud.com/role-name: role_name
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cert-sync-role
  namespace: your_namespace
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    # Least Privilege: Only watch the specific TLS secret
    resourceNames: ["your_secret_name"] 
    verbs: ["get", "watch", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cert-sync-rb
  namespace: your_namespace
subjects:
  - kind: ServiceAccount
    name: cert-sync-sa
roleRef:
  kind: Role
  name: cert-sync-role
  apiGroup: rbac.authorization.k8s.io

```

### 2. Deploy the Operator

Apply the deployment (ensure `pod-identity.alibabacloud.com/injection: "on"` is set to enable RRSA).

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cert-sync-operator
  namespace: your_namespace
spec:
  template:
    metadata:
      labels:
        pod-identity.alibabacloud.com/injection: "on"
    spec:
      serviceAccountName: cert-sync-sa
      containers:
        - name: shell-operator
          image: ghcr.io/daxingplay/alibabacloud-ack-waf-cert-sync-operator:latest
          env:
            - name: SYNC_SECRET_NAME
              value: "your_secret_name"
            - name: SYNC_SECRET_NAMESPACE
              value: "your_namespace"
            - name: CERT_NAME_PREFIX
              value: "cert"
            - name: ALIBABA_REGION_ID
              value: "cn-hangzhou"
            - name: ALIBABA_WAF_INSTANCE_ID
              value: "waf_v2_public_cn-lbxxxxxx"
            - name: ALIBABA_CLB_ID
              value: "lb-xxxx"
            # WAF Listener Settings
            - name: TLS_VERSION
              value: "tlsv1.2"
            - name: ENABLE_TLS_V3
              value: "true"
            - name: CIPHER_SUITE
              value: "2"

```

---

## ⚙️ Configuration Parameters

| Variable | Description | Example |
| --- | --- | --- |
| `SYNC_SECRET_NAME` | The K8s Secret name to watch | `your_secret_name` |
| `SYNC_SECRET_NAMESPACE` | Namespace of the Secret | `your_namespace` |
| `CERT_NAME_PREFIX` | Prefix for the cert name in CAS | `k8s-sync` |
| `ALIBABA_REGION_ID` | Alibaba Cloud Region | `cn-hangzhou` |
| `ALIBABA_WAF_INSTANCE_ID` | Your WAF Instance ID | `waf_v2_...` |
| `ALIBABA_CLB_ID` | The CLB Resource ID in WAF | `lb-xxxx` |
| `TLS_VERSION` | Min TLS Version for WAF | `tlsv1.2` |
| `CIPHER_SUITE` | WAF Cipher Suite ID | `2` |

---

## 🔍 How it Works

1. **Trigger:** `shell-operator` watches the K8s API. When the Secret `your_secret_name` is updated by `cert-manager`, the hook script runs.
2. **Identification:** The script extracts the public cert and calculates the **SHA-1 Fingerprint**.
3. **Verification:** It calls `cas:ListUserCertificateOrder` and searches for a matching fingerprint.
4. **Action:** * If **Found**: It skips the upload and uses the existing `CertificateId`.
* If **Not Found**: It uploads the cert to CAS using the name `${CERT_NAME_PREFIX}-YYYY-MM-DD`.


5. **Synchronization:** It executes `waf-openapi:ModifyCloudResource` to point your WAF listener to the new `CertificateId`.