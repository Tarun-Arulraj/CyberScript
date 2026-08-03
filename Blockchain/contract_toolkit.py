#!/usr/bin/env python3
"""
contract_toolkit.py -- Interact with a CTF blockchain challenge contract and
grep decompiled/source Solidity for common vulnerability patterns
(reentrancy, unchecked external calls, tx.origin auth, integer issues).

Requires: pip install web3

Usage:
    python3 contract_toolkit.py connect --rpc http://localhost:8545 --address 0xABC...
    python3 contract_toolkit.py grep-vulns contract_source.sol
    python3 contract_toolkit.py call --rpc http://localhost:8545 --address 0xABC... \\
        --abi abi.json --function balanceOf --args '["0xYourAddr"]'
"""
import argparse
import json
import re


VULN_PATTERNS = [
    (r"\.call\{value:", "Low-level .call{value:}() -- check for reentrancy (does state update happen BEFORE this call?)"),
    (r"\.call\(", "Low-level .call() -- unchecked return value can silently fail; also reentrancy risk"),
    (r"tx\.origin", "tx.origin used for auth -- vulnerable to phishing-style contract-in-the-middle attacks"),
    (r"block\.timestamp", "block.timestamp used -- miners can manipulate slightly; risky for randomness/critical logic"),
    (r"blockhash\(", "blockhash used for randomness -- predictable/manipulable, classic weak-RNG bug"),
    (r"selfdestruct", "selfdestruct present -- check who can call it and whether it can be abused to force-send ETH"),
    (r"delegatecall", "delegatecall present -- storage collision / arbitrary code execution risk if target is attacker-controlled"),
    (r"unchecked\s*\{", "unchecked block -- overflow/underflow protections bypassed here deliberately, review the math"),
    (r"\bassembly\b", "inline assembly -- bypasses Solidity safety checks, review carefully"),
    (r"public\s+.*initialize", "initializer pattern -- check if it can be called multiple times (missing initializer guard)"),
    (r"\.transfer\(|\.send\(", "old-style ETH transfer -- 2300 gas stipend can break with proxy/multisig recipients, but generally reentrancy-safe"),
]


def grep_vulns(source_path):
    with open(source_path, "r") as f:
        source = f.read()

    print(f"[*] Scanning {source_path} for common vulnerability patterns ...\n")
    found_any = False
    for pattern, description in VULN_PATTERNS:
        matches = list(re.finditer(pattern, source))
        if matches:
            found_any = True
            print(f"[!] Pattern `{pattern}` found ({len(matches)}x):")
            print(f"    -> {description}")
            for m in matches[:3]:
                line_no = source[:m.start()].count("\n") + 1
                print(f"       line {line_no}")
            print()
    if not found_any:
        print("[-] No common patterns matched -- inspect manually, or the bug may be in the challenge's setup/deploy script.")


def connect_and_inspect(rpc, address):
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(rpc))
    print(f"[*] Connected: {w3.is_connected()}")
    print(f"[*] Chain ID: {w3.eth.chain_id}")
    balance = w3.eth.get_balance(address)
    print(f"[*] Contract balance: {w3.from_wei(balance, 'ether')} ETH")
    code = w3.eth.get_code(address)
    print(f"[*] Bytecode length: {len(code)} bytes")
    if len(code) == 0:
        print("[!] No code at this address -- check the address/network.")


def call_function(rpc, address, abi_path, function_name, args_json, private_key=None, value=0):
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(rpc))
    with open(abi_path) as f:
        abi = json.load(f)
    contract = w3.eth.contract(address=Web3.to_checksum_address(address), abi=abi)
    args = json.loads(args_json) if args_json else []

    func = getattr(contract.functions, function_name)(*args)

    # Try as a read-only call first
    try:
        result = func.call()
        print(f"[+] Read-only call result: {result}")
        return result
    except Exception as e:
        print(f"[i] Read-only call failed or function is state-changing: {e}")

    if private_key:
        account = w3.eth.account.from_key(private_key)
        tx = func.build_transaction({
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "value": value,
        })
        signed = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        print(f"[+] Transaction sent: {tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"[+] Receipt status: {receipt.status}")
    else:
        print("[i] Provide --private-key to send a real state-changing transaction.")


def main():
    ap = argparse.ArgumentParser(description="Blockchain CTF contract toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_grep = sub.add_parser("grep-vulns")
    p_grep.add_argument("source_file")

    p_conn = sub.add_parser("connect")
    p_conn.add_argument("--rpc", required=True)
    p_conn.add_argument("--address", required=True)

    p_call = sub.add_parser("call")
    p_call.add_argument("--rpc", required=True)
    p_call.add_argument("--address", required=True)
    p_call.add_argument("--abi", required=True)
    p_call.add_argument("--function", required=True)
    p_call.add_argument("--args", default="[]")
    p_call.add_argument("--private-key")
    p_call.add_argument("--value", type=int, default=0)

    args = ap.parse_args()

    if args.cmd == "grep-vulns":
        grep_vulns(args.source_file)
    elif args.cmd == "connect":
        connect_and_inspect(args.rpc, args.address)
    elif args.cmd == "call":
        call_function(args.rpc, args.address, args.abi, args.function, args.args,
                       args.private_key, args.value)


if __name__ == "__main__":
    main()
