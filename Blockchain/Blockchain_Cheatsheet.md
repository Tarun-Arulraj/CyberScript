# Blockchain CTF Cheatsheet — Speed Edition

*Built around common defaults: Foundry (forge/cast/anvil), web3.py, Remix IDE, Slither,
solc, MythX/Mythril, ethers.js/web3.js. Swap in your actual installed set once you send it.*

---

```bash
cast --version                        # Foundry's Swiss-army CLI for chain interaction
anvil                                 # spin up a local test chain instantly (forked or fresh)
forge --version                       # Foundry's build/test/deploy tool
```

**Quick classification — what kind of blockchain challenge is this?**

| Given | Likely challenge type |
|---|---|
| `.sol` source file + deployed address | Read the source, find the vuln, write an exploit contract |
| Only bytecode, no source | Decompile first (Dedaub/panoramix), then hunt for the vuln |
| RPC endpoint + private key | You have a wallet, need to interact with a contract to "win" |
| Signature verification logic | ECDSA nonce reuse / signature malleability likely |
| Custom token / DeFi-style contract | Reentrancy, flash-loan-style manipulation, or price-oracle attack |
| Puzzle involving `tx.origin` | Phishing-style contract-in-the-middle auth bypass |

---

## 1. Local Chain Setup & Interaction (Foundry)

```bash
anvil                                            # local chain on 127.0.0.1:8545, 10 funded accounts
anvil --fork-url <mainnet_rpc_url>                # fork mainnet state locally (for real-protocol challenges)

cast balance <address> --rpc-url http://localhost:8545
cast send <address> "functionName(uint256)" 123 --private-key <key> --rpc-url <rpc>
cast call <address> "balanceOf(address)(uint256)" <addr> --rpc-url <rpc>     # read-only call
cast code <address> --rpc-url <rpc>               # get deployed bytecode
cast storage <address> <slot> --rpc-url <rpc>     # read raw storage slot (bypasses visibility!)
cast sig "transfer(address,uint256)"              # get a function's 4-byte selector
cast 4byte <selector>                             # reverse-lookup a selector to function signature (public DB)
```

**Reading "private" state — storage is never actually private on-chain:**
```bash
# Every storage slot is readable regardless of Solidity visibility modifiers
cast storage <address> 0 --rpc-url <rpc>          # slot 0 (often the first declared state variable)
cast storage <address> 1 --rpc-url <rpc>          # slot 1, etc -- walk slots to find hidden values
```

---

## 2. Solidity Source Analysis

**Slither — automated static analysis for common vulnerability classes:**
```bash
slither ./contracts/Challenge.sol
slither ./contracts/Challenge.sol --print human-summary     # quick readable overview
slither ./contracts/Challenge.sol --detect reentrancy-eth,tx-origin,unchecked-transfer
```

**Mythril/MythX — symbolic execution for deeper vuln discovery:**
```bash
myth analyze ./contracts/Challenge.sol
myth analyze -a <address> --rpc <rpc_url>          # analyze a deployed contract directly
```

**Manual grep patterns (fast pass before running heavier tools):**

| Pattern | Risk |
|---|---|
| `.call{value:}(` before state update | Reentrancy |
| `tx.origin ==` | Phishing/proxy auth bypass |
| `block.timestamp` / `blockhash` used for randomness | Predictable RNG |
| `delegatecall` to a user-controlled address | Storage collision / arbitrary code exec |
| `selfdestruct` reachable by non-owner | Forced ETH send / contract destruction |
| Missing `initializer` modifier on an `initialize()` function | Re-initialization attack (proxy pattern bug) |
| Unchecked `.transfer()`/`.send()` return value | Silent failure, funds stuck or logic bypass |

---

## 3. No Source Given — Decompiling Bytecode

```bash
cast code <address> --rpc-url <rpc> > bytecode.txt
# Paste into Dedaub's decompiler (dedaub.com) or panoramix (open-source alternative) for pseudo-Solidity
```

```bash
# ABI recovery from bytecode if no ABI given -- extract 4-byte selectors present in the code
cast 4byte-decode <bytecode_or_calldata>          # decode calldata back to function+args if you have a tx
```

---

## 4. Common Attack Patterns

**Reentrancy (classic + read-only variants):**
```solidity
// Attacker contract skeleton
contract Attacker {
    Target target;
    constructor(address _target) { target = Target(_target); }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw();          // triggers receive(), which re-enters before balance is zeroed
    }

    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw();      // re-enter again
        }
    }
}
```

**Flash loan / price oracle manipulation:** borrow a huge amount within one transaction,
manipulate a DEX pool's price via a large swap, exploit a contract that reads that
manipulated spot price, repay the loan — all atomic within a single tx. Look for any
`getPrice()` that reads directly from a pool's reserves rather than a TWAP/oracle.

**Signature replay / malleability:**
```bash
# If a contract checks a signature but doesn't track used nonces/hashes, replay it:
cast send <address> "claim(uint256,bytes)" <amount> <same_signature_bytes> --private-key <key> --rpc-url <rpc>
```

---

## 5. web3.py — Scripted Interaction

```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
contract = w3.eth.contract(address=addr, abi=abi)

# Read
print(contract.functions.balanceOf(my_address).call())

# Write (needs a signed tx)
tx = contract.functions.transfer(target, 100).build_transaction({
    'from': my_address,
    'nonce': w3.eth.get_transaction_count(my_address),
})
signed = w3.eth.account.sign_transaction(tx, private_key)
w3.eth.send_raw_transaction(signed.raw_transaction)
```

(see `contract_toolkit.py` in your Blockchain toolkit repo for a ready-made wrapper)

---

## 6. Quick Reference — CTF Triage Checklist

**Given a .sol file + address:**
```
Read source manually first (5 min) → grep for the vuln table patterns above →
run Slither for anything missed → write exploit contract or cast calldata → cast send it
```

**Given only bytecode:**
```
cast code to dump bytecode → decompile via Dedaub/panoramix →
identify function selectors via cast 4byte → treat like source-available from there
```

**"Read this private variable" style challenge:**
```
cast storage at slot 0, 1, 2... to walk state → private just means no getter,
NOT actually hidden on-chain
```

**DeFi-style / price manipulation challenge:**
```
Check if price comes from pool reserves directly (manipulable) vs a TWAP/oracle →
anvil --fork-url to test against real mainnet state locally before touching the real target
```

---
