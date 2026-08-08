# InCTF Finals — "First 5 Minutes" Playbook
What to do the moment you open a challenge, per domain. Skim this, don't study it.

---

## 🌐 WEB

**First move:** open it in browser, view source, then hit it with curl.

```bash
curl -isk http://target/          # headers + body in one shot
```

**Look at, in this order:**
1. Response headers — `Server`, `X-Powered-By` tell you the stack (PHP? Node? Java?)
2. Page source — HTML comments, JS files (endpoints/API keys hide here)
3. `robots.txt`, `/.git/`, `/.env`, `/admin`
4. Cookies — is there a JWT? Decode it immediately (`jwt_helper.py decode`)

**Then run:**
```bash
python3 web_recon.py http://target --paths
```

**Ask yourself:** what does the challenge NAME hint at? "vault", "upload", "template", "fetch" — these are direct hints (SSRF, LFI, SSTI, upload vuln). Don't test everything blindly — test the hinted class first.

**If totally stuck:** `python3 web_swiss_army.py http://target` — runs every quick probe (SQLi/XSS/SSTI/IDOR signals) in one go.

---

## 💥 PWN

**First move:**
```bash
file ./binary                     # arch, stripped?, static/dynamic
checksec ./binary                 # NX, PIE, canary, RELRO — decides your approach
```

**Read this like a decision tree:**
- No canary + no NX → shellcode on stack, straightforward
- NX on, no PIE → ROP/ret2libc, addresses are static — easy to hardcode
- PIE on → need an info leak first before you can ROP
- Canary on → need a leak or an overwrite that skips the canary (e.g. via a pointer, not linear overflow)

```bash
gdb -q ./binary                   # or gef/pwndbg if loaded
pwn checksec ./binary             # pwntools' own version, cleaner output
```

**Find the crash first, always:**
```python
from pwn import *
io = process('./binary')
io.sendline(b'A'*200)
io.interactive()
```
See if it segfaults, then binary-search the offset with a cyclic pattern:
```python
print(cyclic(200))
# after crash: cyclic_find(<value in EIP/RIP>)
```

**Then:** decide ret2win / ROP / shellcode based on checksec results above, use `rop_chain_auto.py` or `find_offset.py` from the repo.

---

## 🔐 CRYPTO

**First move:** figure out WHAT you're attacking before touching any tool.

**Look at the given data and ask:**
- Is there an `n`, `e`, ciphertext? → RSA. Check `n` for small factors first (`factordb` won't work offline — use `rsa_toolkit.py --offline` or `sympy.factorint`)
- Fixed-length blocks, no obvious structure? → AES (check mode: ECB shows patterns if you look at ciphertext blocks visually, CBC/CTR need IV)
- Curve params, nonce reused across signatures? → ECDSA/ECC — nonce reuse = instant private key recovery
- Weird repeating XOR-looking output? → XOR cipher, try key-length guessing (Kasiski/IC) before brute force
- Numbers only, no crypto structure? → classic cipher (Caesar/Vigenère) or a custom cipher — read the source if given

**Quick checks:**
```bash
python3 -c "print(len('<ciphertext>'))"   # block-size multiples hint at AES
openssl enc -d -aes-256-cbc -in ct.bin -k KEY   # if you already have/guess a key
```

**Golden rule:** if source/script is given, READ IT FULLY before attacking — custom crypto challenges almost always have the bug baked into a specific implementation detail (bad randomness, reused nonce, weak modulus), not the underlying math.

---

## 🔍 REVERSE ENGINEERING

**First move:**
```bash
file ./binary
strings ./binary | less           # look for flag format, function names, error messages
```

**Then open in your disassembler** (Ghidra/IDA — whichever's on the image) and:
1. Find `main`, or search for `strcmp`/`strncmp` calls (usually where the flag check happens)
2. Rename variables as you understand them — future you will thank you
3. Check if it's a VM/bytecode challenge (unusual loop over an array with a switch statement = likely custom VM, don't try to reverse it by hand, script it)

**If it just needs a satisfying input (not full understanding):**
```bash
python3 angr_template.py ./binary    # symbolic execution — let the solver find the input
```
Angr is slow to set up right but fast once it's running — worth trying early on constraint-heavy binaries instead of hand-reversing every branch.

**Dynamic beats static when stuck:**
```bash
gdb -q ./binary
# set a breakpoint right after the input is read, single-step through the check
```

---

## 🗂️ FORENSICS

**First move:** identify the file type — never trust the extension.
```bash
file ./evidence
xxd ./evidence | head -20         # check magic bytes by hand if `file` is unsure
binwalk ./evidence                # hidden embedded files?
```

**By evidence type:**
- **PCAP** → open in Wireshark first for a visual pass, `Follow TCP/UDP Stream` on anything interesting, `Export Objects` for files transferred, filter `http`, `ftp-data`, `dns` first
- **Disk/memory image** → `volatility3` — start with `windows.info`/`linux.info` to confirm profile, then `pslist`, `netscan`, `filescan`
- **Image file** → `exiftool` for metadata, `steghide`/`zsteg`/`stegsolve` for hidden data, check LSBs if it's a stego challenge
- **Logs** → `grep` for anomalies (unusual timestamps, repeated failed auth, base64-looking strings), correlate timestamps across multiple log files if given

**Always check first regardless of type:**
```bash
strings ./evidence | grep -i flag
exiftool ./evidence
```

---

## 📱 MOBILE (Android)

**First move:**
```bash
apktool d app.apk -o app_decompiled     # unpack, get readable resources/manifest
jadx-gui app.apk                        # decompiled Java, much more readable than smali
```

**Check in this order:**
1. `AndroidManifest.xml` — exported activities/services (attack surface), permissions
2. `strings.xml` and hardcoded strings in decompiled Java — flags/keys are often just sitting there
3. Any `SharedPreferences` or local DB (`sqlite3` on any `.db` file pulled from the device/emulator)
4. Network calls — if the app talks to a server, Frida + a proxy (Burp) to intercept

**If dynamic analysis needed:**
```bash
frida -U -f com.target.app -l script.js --no-pause
```
Use this when the flag is computed at runtime (native lib call, obfuscated Java) rather than sitting static in the APK.

---

## GENERAL RULES ACROSS ALL DOMAINS

1. **Read the challenge description twice.** The name and description are hints, not flavor text.
2. **Timebox.** If 15-20 min in with zero signal, flag it to a teammate and switch — don't solo-grind a dead end.
3. **Lowest-hanging fruit first** across ALL open challenges before deep-diving one — points add up faster from 3 easy solves than 1 hard one, especially early.
4. **Save your commands as you go** (a scratch `notes.md` per challenge) — you will need to reconstruct your steps for writeups, and it stops you from re-doing work.
5. **Ask a teammate before abandoning** — someone else on the team may have already seen the exact pattern this challenge is using.
