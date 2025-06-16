Here's a clean, informative, and professional `README.md` for your `EKStract.py` script:

---

# 🧪 EKStract

> **IRSA / Pod Identity Credential Extractor for Amazon EKS**

`EKStract.py` is a utility script designed to extract AWS credentials from containers running in Amazon EKS clusters. It supports both **IRSA (IAM Roles for Service Accounts)** and **Pod Identity** methods.

---

## 🔧 Features

* 🔍 Scans running EKS containers using `ctr` and `nsenter`
* 🧾 Extracts OIDC tokens (IRSA) and Pod Identity tokens
* 🔐 Assumes IAM roles via `aws sts assume-role-with-web-identity`
* 📦 Dumps tokens into `tokens/` folder
* 🧪 Outputs environment-ready `*.sh` export scripts
* 🎨 Colorized output with ASCII banner for clarity

---

## 📦 Requirements

* Python 3.6+
* `aws` CLI configured in the host
* `ctr` CLI (for containerd)
* `nsenter`
* Network access to AWS metadata and credential endpoints

Install dependencies (on Amazon Linux 2 or similar):

```bash
sudo yum install -y util-linux awscli
```

---

## 🚀 Usage

### Basic Mode

```bash
./EKStract.py
```

This scans all container PIDs, extracts OIDC and Pod Identity tokens, and writes:

* Tokens in `tokens/` directory
* Credentials in `*.sh` export files

---

### Options

| Option           | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `--tokens-only`  | Only extract and save the tokens, skip assuming roles        |
| `--keys-only`    | Only assume roles and export credentials, skip saving tokens |
| `--role-arn`     | Provide the OIDC IAM Role ARN (if skipping prompt)           |
| `--session-name` | Custom session name for the assumed role                     |
| `--region`       | AWS region (default: `us-west-2`)                            |

Example:

```bash
./EKStract.py --role-arn arn:aws:iam::123456789012:role/MyEksRole --session-name test-session
```

---

## 📁 Output

| File                         | Description                              |
| ---------------------------- | ---------------------------------------- |
| `tokens/oidc_1.token`        | Raw IRSA token from container            |
| `tokens/podidentity_1.token` | Raw Pod Identity token                   |
| `oidc_1.sh`                  | `export` commands for IRSA credentials   |
| `podidentity_1.sh`           | `export` commands for Pod Identity creds |

To use credentials:

```bash
source oidc_1.sh
```

---

## ⚠️ Notes

* Must be run on the host or privileged pod with access to container namespaces.
* Assumes IRSA and Pod Identity volumes are mounted at standard EKS paths:

  * IRSA: `/var/run/secrets/eks.amazonaws.com/serviceaccount/token`
  * Pod Identity: `/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token`
* Pod Identity requires network access to the credential endpoint (`169.254.170.23`).

---

## 🧠 Example Use Cases

* 🔍 Forensics or credential inspection during troubleshooting
* 🔐 Security audits in EKS clusters
* 🔄 Rotating credentials for service accounts

---

## 📜 License

MIT License

---

