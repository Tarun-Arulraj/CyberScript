#!/usr/bin/env python3
"""
cloud_recon.py -- Common cloud-track CTF recon: public S3/GCS bucket
enumeration, IAM/metadata credential checks once inside a pivot, and
basic misconfiguration probing. Assumes you already have some pivot point
(e.g. via SSRF) or a bucket name from challenge recon -- not a scanner
for infrastructure you don't have permission to test.

Requires: pip install boto3 requests

Usage:
    python3 cloud_recon.py s3-check <bucket-name>
    python3 cloud_recon.py gcs-check <bucket-name>
    python3 cloud_recon.py aws-whoami --access-key AKIA... --secret-key ...
    python3 cloud_recon.py aws-enum-perms --access-key AKIA... --secret-key ...
"""
import argparse
import requests


def s3_check(bucket_name):
    """Check common S3 bucket misconfigurations without needing AWS credentials."""
    urls = [
        f"https://{bucket_name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{bucket_name}/",
    ]
    for url in urls:
        try:
            r = requests.get(url, timeout=8)
            print(f"[{r.status_code}] {url}")
            if r.status_code == 200:
                print("[+] Bucket listing may be public! Response snippet:")
                print(r.text[:500])
            elif r.status_code == 403:
                print("    -> Bucket exists but listing is denied (still might allow public GetObject on known keys)")
            elif r.status_code == 404:
                print("    -> Bucket does not exist (or is in a different region -- try adding a region prefix)")
        except requests.RequestException as e:
            print(f"[!] {url} error: {e}")


def gcs_check(bucket_name):
    url = f"https://storage.googleapis.com/{bucket_name}/"
    try:
        r = requests.get(url, timeout=8)
        print(f"[{r.status_code}] {url}")
        if r.status_code == 200:
            print("[+] Bucket listing may be public! Response snippet:")
            print(r.text[:500])
    except requests.RequestException as e:
        print(f"[!] error: {e}")


def aws_whoami(access_key, secret_key, session_token=None):
    import boto3
    sts = boto3.client(
        "sts", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
        aws_session_token=session_token,
    )
    identity = sts.get_caller_identity()
    print("[+] Caller identity:")
    for k, v in identity.items():
        if k != "ResponseMetadata":
            print(f"    {k}: {v}")


def aws_enum_perms(access_key, secret_key, session_token=None):
    """Lightweight permission enumeration -- tries a handful of common,
    low-risk read-only calls to see what the credentials can access.
    For thorough enumeration use the dedicated tool `enumerate-iam` or
    `Pacu` instead of reinventing it here."""
    import boto3
    from botocore.exceptions import ClientError

    session = boto3.Session(
        aws_access_key_id=access_key, aws_secret_access_key=secret_key,
        aws_session_token=session_token,
    )

    checks = [
        ("s3", "list_buckets", {}),
        ("iam", "list_users", {}),
        ("iam", "get_user", {}),
        ("ec2", "describe_instances", {}),
        ("lambda", "list_functions", {}),
        ("secretsmanager", "list_secrets", {}),
        ("dynamodb", "list_tables", {}),
    ]

    for service, method, kwargs in checks:
        try:
            client = session.client(service)
            result = getattr(client, method)(**kwargs)
            print(f"[+] {service}.{method}: ALLOWED")
            # print a tiny summary
            for key in result:
                if key != "ResponseMetadata":
                    val = result[key]
                    summary = val if not isinstance(val, list) else f"{len(val)} item(s)"
                    print(f"      {key}: {summary}")
                    break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            print(f"[-] {service}.{method}: DENIED ({code})")
        except Exception as e:
            print(f"[!] {service}.{method}: error {e}")


def main():
    ap = argparse.ArgumentParser(description="Cloud CTF recon toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_s3 = sub.add_parser("s3-check")
    p_s3.add_argument("bucket")

    p_gcs = sub.add_parser("gcs-check")
    p_gcs.add_argument("bucket")

    p_who = sub.add_parser("aws-whoami")
    p_who.add_argument("--access-key", required=True)
    p_who.add_argument("--secret-key", required=True)
    p_who.add_argument("--session-token")

    p_enum = sub.add_parser("aws-enum-perms")
    p_enum.add_argument("--access-key", required=True)
    p_enum.add_argument("--secret-key", required=True)
    p_enum.add_argument("--session-token")

    args = ap.parse_args()

    if args.cmd == "s3-check":
        s3_check(args.bucket)
    elif args.cmd == "gcs-check":
        gcs_check(args.bucket)
    elif args.cmd == "aws-whoami":
        aws_whoami(args.access_key, args.secret_key, args.session_token)
    elif args.cmd == "aws-enum-perms":
        aws_enum_perms(args.access_key, args.secret_key, args.session_token)


if __name__ == "__main__":
    main()
