#!/usr/bin/env python3
"""
serial_protocol_helper.py -- Helpers for hardware CTF challenges that give
you a logic analyzer capture or raw serial dump instead of physical access:
UART baud detection assistance, and simple I2C/SPI byte-stream decoding
notes when given raw capture data (e.g. from a Saleae/sigrok export CSV).

Requires: pip install pyserial (only needed for --live mode against real hardware)

Usage:
    python3 serial_protocol_helper.py uart-live /dev/ttyUSB0 --baud 115200
    python3 serial_protocol_helper.py uart-bruteforce-baud /dev/ttyUSB0
    python3 serial_protocol_helper.py decode-i2c-csv capture.csv
"""
import argparse
import time

COMMON_BAUDS = [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]


def uart_live(port, baud):
    import serial
    print(f"[*] Opening {port} at {baud} baud ...")
    with serial.Serial(port, baud, timeout=1) as ser:
        print("[*] Reading (Ctrl+C to stop). Send data if you have a terminal open too.")
        try:
            while True:
                data = ser.readline()
                if data:
                    print(data)
        except KeyboardInterrupt:
            pass


def uart_bruteforce_baud(port, sample_seconds=2):
    """Try each common baud rate briefly and print any readable output,
    useful when a challenge gives serial access but not the baud rate."""
    import serial
    for baud in COMMON_BAUDS:
        print(f"\n[*] Trying {baud} baud ...")
        try:
            with serial.Serial(port, baud, timeout=sample_seconds) as ser:
                data = ser.read(256)
                printable_ratio = sum(1 for b in data if 32 <= b <= 126) / max(len(data), 1)
                print(f"    read {len(data)} bytes, {printable_ratio:.0%} printable")
                if printable_ratio > 0.7 and len(data) > 5:
                    print(f"    [+] Likely correct baud rate: {baud}")
                    print(f"    sample: {data}")
        except Exception as e:
            print(f"    [!] error: {e}")


def decode_i2c_csv(csv_path):
    """
    Parses a simple logic-analyzer CSV export (time, SDA, SCL columns) and
    reconstructs I2C transactions. Real captures usually come pre-decoded by
    sigrok/PulseView's I2C protocol decoder -- prefer that when available;
    this is a fallback for raw two-channel exports.
    """
    import csv as csv_module

    print(f"[*] Reading {csv_path} ... (expects columns: time,sda,scl or similar)")
    print("[i] For real captures, decode with sigrok instead, e.g.:")
    print("    sigrok-cli -i capture.sr -P i2c:scl=SCL:sda=SDA -A i2c=address-read-write:data-read:data-write")
    print("    or open in PulseView and add the 'I2C' protocol decoder.")
    with open(csv_path) as f:
        reader = csv_module.reader(f)
        header = next(reader)
        print(f"[*] CSV columns detected: {header}")
        row_count = sum(1 for _ in reader)
        print(f"[*] {row_count} sample rows -- manual reconstruction from raw SDA/SCL is slow;")
        print("    strongly recommend the sigrok decoder path above for real analysis.")


def main():
    ap = argparse.ArgumentParser(description="Hardware serial/protocol helper")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_live = sub.add_parser("uart-live")
    p_live.add_argument("port")
    p_live.add_argument("--baud", type=int, default=115200)

    p_brute = sub.add_parser("uart-bruteforce-baud")
    p_brute.add_argument("port")

    p_i2c = sub.add_parser("decode-i2c-csv")
    p_i2c.add_argument("csv_path")

    args = ap.parse_args()

    if args.cmd == "uart-live":
        uart_live(args.port, args.baud)
    elif args.cmd == "uart-bruteforce-baud":
        uart_bruteforce_baud(args.port)
    elif args.cmd == "decode-i2c-csv":
        decode_i2c_csv(args.csv_path)


if __name__ == "__main__":
    main()
