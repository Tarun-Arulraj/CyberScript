#!/usr/bin/env python3
"""
pcap_creds_extract.py -- Pull cleartext credentials, HTTP objects, and DNS
queries out of a pcap using pyshark/tshark. A very common forensics-track
CTF pattern: "find the password sent over the wire."

Requires: pip install pyshark  (needs tshark installed on the system)

Usage:
    python3 pcap_creds_extract.py capture.pcapng --creds
    python3 pcap_creds_extract.py capture.pcapng --http-objects ./extracted
    python3 pcap_creds_extract.py capture.pcapng --dns
"""
import argparse
import os
import pyshark


def extract_ftp_creds(pcap_path):
    print("[*] Scanning FTP traffic for credentials ...")
    cap = pyshark.FileCapture(pcap_path, display_filter="ftp")
    for pkt in cap:
        try:
            req = pkt.ftp.request_command
            if req in ("USER", "PASS"):
                print(f"  FTP {req}: {pkt.ftp.request_arg}")
        except AttributeError:
            continue
    cap.close()


def extract_http_creds(pcap_path):
    print("[*] Scanning HTTP traffic for Basic Auth / form credentials ...")
    cap = pyshark.FileCapture(pcap_path, display_filter="http.authorization or http.request.method==POST")
    for pkt in cap:
        try:
            if hasattr(pkt.http, "authorization"):
                print(f"  HTTP Authorization header: {pkt.http.authorization}")
        except AttributeError:
            pass
        try:
            if hasattr(pkt.http, "file_data"):
                data = pkt.http.file_data
                if any(k in str(data).lower() for k in ("user", "pass", "login", "pwd")):
                    print(f"  HTTP POST body (possible creds): {data}")
        except AttributeError:
            pass
    cap.close()


def extract_telnet(pcap_path):
    print("[*] Scanning Telnet traffic (fully cleartext) ...")
    cap = pyshark.FileCapture(pcap_path, display_filter="telnet")
    for pkt in cap:
        try:
            print(f"  Telnet data: {pkt.telnet.data}")
        except AttributeError:
            continue
    cap.close()


def extract_http_objects(pcap_path, outdir):
    """Equivalent of `tshark -r file.pcap --export-objects http,outdir`."""
    os.makedirs(outdir, exist_ok=True)
    import subprocess
    cmd = ["tshark", "-r", pcap_path, "--export-objects", f"http,{outdir}"]
    print(f"[*] Running: {' '.join(cmd)}")
    subprocess.run(cmd)
    print(f"[+] Extracted objects (if any) written to {outdir}")


def extract_dns(pcap_path):
    print("[*] Listing DNS queries (can reveal C2 domains / hidden hosts) ...")
    cap = pyshark.FileCapture(pcap_path, display_filter="dns.flags.response==0")
    seen = set()
    for pkt in cap:
        try:
            qname = pkt.dns.qry_name
            if qname not in seen:
                seen.add(qname)
                print(f"  {qname}")
        except AttributeError:
            continue
    cap.close()


def main():
    ap = argparse.ArgumentParser(description="Extract credentials/artifacts from a pcap")
    ap.add_argument("pcap")
    ap.add_argument("--creds", action="store_true", help="scan FTP/HTTP/Telnet for cleartext creds")
    ap.add_argument("--http-objects", metavar="OUTDIR", help="extract HTTP file transfers to OUTDIR")
    ap.add_argument("--dns", action="store_true", help="list unique DNS queries")
    args = ap.parse_args()

    if args.creds:
        extract_ftp_creds(args.pcap)
        extract_http_creds(args.pcap)
        extract_telnet(args.pcap)
    if args.http_objects:
        extract_http_objects(args.pcap, args.http_objects)
    if args.dns:
        extract_dns(args.pcap)
    if not (args.creds or args.http_objects or args.dns):
        print("Specify --creds, --http-objects OUTDIR, and/or --dns")


if __name__ == "__main__":
    main()
