# Reverse Engineering CTF Cheatsheet — Command Reference Companion

*Tooling note: built around Ghidra, radare2/Cutter, IDA Free, objdump/readelf/nm/
strings/file, gdb+GEF/pwndbg/peda, x64dbg, dnSpy/ILSpy, JD-GUI/CFR/Procyon, Frida,
apktool/jadx, upx, capstone/keystone/unicorn, YARA, Detect It Easy (DIE).
Binary Ninja is request-only — see section 2 for when it's actually worth requesting.*

*Pairs with your existing Reverse Engineering Checklist (workflow/methodology).
This sheet is the dense command-lookup layer: format ID, tool commands,
anti-debug/packer bypass, ROP hunting, and non-C-language binaries.*

---

```bash
file ./binary                        # format, arch, static/dynamic, stripped?
checksec --file=./binary             # canary/NX/PIE/RELRO/Fortify
readelf -h ./binary                  # ELF header (entry point, arch, type)
nm ./binary 2>&1 | head              # symbols (empty/error = stripped)
```

**Magic bytes / format ID table:**

| Format | Hex signature |
|---|---|
| ELF (Linux) | `7F 45 4C 46` |
| PE (Windows .exe/.dll) | `4D 5A` (MZ) |
| Mach-O 32-bit | `FE ED FA CE` |
| Mach-O 64-bit | `FE ED FA CF` |
| Java class file | `CA FE BA BE` |
| .NET assembly | PE header + CLR header (check with `file` — says ".Net assembly") |
| WASM | `00 61 73 6D` |

**Architecture quick ID (from `file` output or `readelf -h`):**

| Machine field | Arch |
|---|---|
| Advanced Micro Devices X86-64 | x86-64 |
| Intel 80386 | x86 (32-bit) |
| ARM | ARM32 |
| AArch64 | ARM64 |
| MIPS | MIPS |

---

## 1. First-Pass Triage (fills gaps beyond your existing "First 10 Commands")

```bash
strings -n 8 ./binary | grep -Ei 'flag|password|key|http|/bin/sh|debug'
ldd ./binary                          # dynamic library dependencies
objdump -T ./binary                   # dynamic symbol table (imports, if dynamically linked)
objdump -d ./binary -M intel | less   # Intel syntax disassembly (easier to read than AT&T)
readelf -d ./binary                   # dynamic section (NEEDED libs, RUNPATH)
readelf --dyn-syms ./binary           # dynamic symbols only
python3 -c "print(open('./binary','rb').read()[:4])"   # raw magic bytes check
```

**Stripped binary? Recover function boundaries without symbols:**
```bash
r2 -A ./binary -qc 'afl' -            # radare2 auto-analysis, list detected functions
ghidra   # auto-analysis still finds function boundaries via prologue patterns even when stripped
```

---

## 2. Packers / Obfuscation / Compiler Fingerprinting

**Detect It Easy (DIE) — always run this first, identifies packer/compiler/language in one shot:**
```bash
diec ./binary                          # CLI version, quick automated scan
die ./binary                           # GUI version, shows detailed signature matches + entropy graph
```
DIE tells you packer (UPX, ASPack, Themida, etc), compiler (GCC/MSVC/MinGW/Go/Rust),
and language/runtime — saves the manual `file`/`strings` guessing below in most cases.

```bash
file ./binary                          # fallback if DIE unavailable, sometimes flags "UPX compressed"
strings ./binary | grep -i upx         # UPX leaves markers even when packed
upx -d ./binary -o unpacked            # unpack UPX (most common CTF packer)
binwalk ./binary                       # detect embedded/appended data, other packer signatures

# If unpacking fails/custom packer: dump memory after it self-unpacks
gdb -q ./binary
(gdb) break *entry_point
(gdb) run
(gdb) # single-step past the unpacking stub, then:
(gdb) dump memory unpacked.bin <start_addr> <end_addr>
```

**Common obfuscation tells:** huge blob of high-entropy bytes in `.data`/`.rodata`, tiny `.text` section, single suspicious function called from `_start` before `main`, `mprotect`/`mmap` calls with `PROT_EXEC` right before a jump to a computed address. DIE's entropy graph view will visually flag these regions instantly.

**IDA Free vs requesting Binary Ninja:**
IDA Free covers x86/x64 disassembly fine but has **no Hex-Rays decompiler** and no
ARM/MIPS decompilation. For those cases, prefer **Ghidra** (free, full decompiler,
all archs) first — it covers almost everything IDA Free can't. Only request
**Binary Ninja** when you specifically need: its scripting API for batch/automated
analysis across many binaries, or its (paid-tier-adjacent) decompiler output style
differs enough from Ghidra's to unstick a specific confusing function. For a single
CTF binary, Ghidra is almost always sufficient — don't request Binary Ninja by default.

---

## 3. Anti-Debugging Bypass

```bash
strings ./binary | grep -iE 'ptrace|IsDebuggerPresent|CheckRemoteDebuggerPresent'
objdump -d ./binary | grep -B2 -A2 'call.*ptrace'   # find the anti-debug check location
```

| Technique found | Bypass |
|---|---|
| `ptrace(PTRACE_TRACEME, ...)` self-check | Patch the call to always return 0 (nop it out), or use `gdb`'s `catch syscall ptrace` + change return value |
| Timing checks (`rdtsc`, `gettimeofday` around a loop) | Patch out the comparison/jump, or use `LD_PRELOAD` to fake `gettimeofday` |
| `IsDebuggerPresent` (Windows) | Patch return value to 0, or use x64dbg's built-in hide-debugger plugin (ScyllaHide) |
| Checks `/proc/self/status` `TracerPid` field | Patch the check, or use a kernel-level bypass (rare in CTF, usually just patch) |
| Parent process check (`getppid`) | Run under a wrapper so your debugger isn't the direct parent, or patch |

```bash
# Quick patch-out with radare2 (nop a conditional jump at an address)
r2 -w ./binary
[0x...]> s <address>
[0x...]> wa nop      # write a nop over the jump instruction
```

---

## 4. Static Analysis — Tool Command References

**pyelftools — programmatic ELF parsing when you want to script the analysis instead of eyeballing readelf output:**
```python
from elftools.elf.elffile import ELFFile

with open('./binary', 'rb') as f:
    elf = ELFFile(f)
    print("Entry point:", hex(elf.header['e_entry']))
    for section in elf.iter_sections():
        print(section.name, hex(section['sh_addr']), section['sh_size'])
    symtab = elf.get_section_by_name('.symtab')
    if symtab:
        for sym in symtab.iter_symbols():
            print(sym.name, hex(sym['st_value']))
```
Useful for batch-processing many binaries in a challenge set (e.g. "find every binary
with an exported function named `check_flag`") rather than opening each one manually.

**radare2 / rizin (expanded beyond your checklist):**

*(Cutter is r2's Qt GUI frontend — same engine, same commands available via its
built-in console, but with graph view/decompiler-panel/hex-view all visible at
once. Use Cutter when you want the visual graph without leaving r2's ecosystem;
use raw r2 CLI when scripting or when you just need one quick lookup.)*

```bash
r2 -d -AA ./binary
aaa                        # full analysis (do this first, always)
afl                        # list all functions
afl~main                   # grep functions for "main"
pdf @ main                 # disassemble a function
pdg @ main                 # DECOMPILE a function (pseudo-C, huge time-saver)
axt @ sym.flag             # who references this symbol
s main; V                  # seek to main, enter visual mode
Vp                         # visual mode -> graph view
iz                         # list strings in binary
izz                        # list ALL strings including non-.rodata
ii                         # list imports
ic                         # list classes (for OOP binaries, C++/Java-on-native)
/c flag                    # search for byte pattern "flag"
```

**Ghidra scripting (headless, for batch/automated analysis):**
```bash
$GHIDRA_HOME/support/analyzeHeadless <project_dir> <project_name> \
    -import ./binary -postScript DecompileAll.java -deleteProject
```
(see `ghidra_headless_analyze.sh` in your toolkit repo for a ready script)

**IDA Pro keyboard shortcuts (if available):**
| Key | Action |
|---|---|
| `N` | rename |
| `G` | goto address |
| `;` | comment |
| `X` | cross-references to this |
| `Space` | toggle graph/text view |
| `F5` | Hex-Rays decompile (if licensed) |

---

## 5. Dynamic Analysis — Extra GDB/pwndbg Patterns

```bash
gdb -q ./binary
pwndbg> break *main
pwndbg> run
pwndbg> context                # pwndbg auto-shows regs/stack/disasm/backtrace
pwndbg> telescope $rsp 20       # pretty-print 20 stack slots, resolves pointers
pwndbg> vmmap                   # memory mapping (find PIE base at runtime)
pwndbg> got                     # dump GOT table (spot unresolved/hooked entries)
pwndbg> heap                    # heap chunk overview
pwndbg> bins                    # tcache/fastbin/unsorted bin state
pwndbg> patch <addr> "\x90\x90" # patch bytes live in memory (not on disk)
pwndbg> nearpc                  # disasm near current instruction
```

```bash
# ltrace/strace for black-box behavior without opening a disassembler at all
ltrace -f ./binary                 # library calls (strcmp, malloc, etc) - great for quick wins
strace -f ./binary                 # syscalls (open, read, ptrace anti-debug, etc)
strace -f -e trace=network ./binary   # only network syscalls (for challenges that phone home)
```

---

## 6. Frida — Dynamic Instrumentation (not just for mobile)

```bash
frida-ps -U                                    # list processes on a USB-connected device
frida-ps -D <device_id>                        # list processes on a specific device
frida -f ./binary --no-pause                   # spawn + attach to a local binary directly
frida -p <pid> -l script.js                    # attach to a running process, inject a script
frida-trace -i "strcmp*" ./binary               # auto-trace every call matching a pattern (great first look)
frida-trace -i "malloc" -i "free" ./binary      # trace multiple functions at once
```

**Quick inline hook (no separate script file needed) to log a function's args/return:**
```bash
frida -f ./binary --no-pause -e '
Interceptor.attach(Module.getExportByName(null, "strcmp"), {
  onEnter: function (args) {
    console.log("strcmp:", args[0].readCString(), "vs", args[1].readCString());
  },
  onLeave: function (retval) {
    console.log("-> returned:", retval);
  }
});
'
```

Useful when a CTF binary's core check is a library call (`strcmp`/`memcmp`/`atoi`) you'd
otherwise have to find manually in the disassembly — Frida lets you watch it live without
setting a single breakpoint.

---

## 7. Non-C Language Binaries (increasingly common in modern CTFs)

**Go binaries:**
```bash
file ./binary                       # often says "Go BuildID"
strings ./binary | grep -i "go1\."  # Go version
go tool objdump -s main.main ./binary   # if you have Go toolchain
# Function names often survive even when "stripped" -- Go embeds its own runtime metadata
strings ./binary | grep -E '^(main\.|runtime\.)'
```

**Rust binaries:**
```bash
# Rust demangling - names look like _ZN4core...17h<hash>E
rustfilt < mangled_names.txt          # demangle Rust symbol names
c++filt < mangled_names.txt           # also works for many Rust symbols (Itanium-ish mangling)
nm ./binary | rustfilt                # demangle in one step
```

**.NET assemblies:**
```bash
# Use dnSpy / ILSpy / dotPeek (GUI) for full C# decompilation -- much easier than raw IL
ilasm / ildasm ./binary.exe            # disassemble to IL text (Windows/mono toolchain)
monodis ./binary.exe                   # Mono's IL disassembler (cross-platform)
```

**Java:**
```bash
javap -c -p MyClass.class              # disassemble bytecode
jd-gui MyApp.jar                       # GUI decompiler, gives readable Java source
cfr MyApp.jar                          # CLI decompiler alternative
unzip -l app.jar                       # list classes inside a jar first
```

---

## 8. ROP / Gadget Hunting (overlaps with PWN, useful when rev challenge has exploitation component)

```bash
ROPgadget --binary ./binary | grep 'pop rdi'      # find useful gadgets
ropper --file ./binary --search "pop rdi"         # alternative tool, nicer search syntax
objdump -d ./binary | grep -B2 'ret$'             # manual gadget hunting
```

---

## 9. Binary Diffing (patched-binary / "what changed" challenges)

```bash
diff <(objdump -d binary_v1) <(objdump -d binary_v2) | head -50
radiff2 -A binary_v1 binary_v2         # radare2's built-in binary diff
# For heavier lifting: BinDiff (Google) or Diaphora (free, IDA/Ghidra plugin)
```

---

## 10. YARA — Pattern/Signature Matching

Useful for: identifying which family/CTF-series a binary belongs to (if the organizers
reuse a custom packer/protector across challenges), or writing your own rule once you've
found the flag-decryption routine's byte pattern so you can scan other binaries in the
same challenge set instantly.

```bash
yara rule.yar ./binary                      # scan one binary against a rule file
yara -r rule.yar ./binary_directory/        # recursive scan of a directory of binaries
yara -s rule.yar ./binary                   # print matched strings, not just rule name
```

**Minimal rule template (match a known byte sequence, e.g. a custom XOR loop signature):**
```yara
rule custom_xor_loop
{
    strings:
        $sig = { 48 89 C1 48 31 D1 48 89 C8 }   // example opcode bytes, replace with your find
        $flag_prefix = "flag{" ascii wide
    condition:
        $sig or $flag_prefix
}
```

**Pull public rule sets instead of writing from scratch when possible:**
```bash
git clone https://github.com/Yara-Rules/rules.git      # community rules (mostly malware-focused,
yara -r rules/malware/ ./binary                          # but packer/crypter signatures overlap with CTF packers)
```

---

## 11. Quick greps for RE specifically

```bash
strings ./binary | grep -oE "flag\{[^}]{1,100}\}"          # bounded flag pattern
objdump -d ./binary | grep -E '<(system|exec|popen)@plt>'  # dangerous calls
objdump -d ./binary | grep -E 'call.*strcmp|call.*memcmp'  # comparison-based checks (license/serial validation)
strings ./binary | grep -iE '^[A-Za-z0-9+/]{16,}={0,2}$'   # base64 blobs (often the encoded flag or key)
```

---

## 12. Quick Reference — CTF Triage Checklist

**Unknown binary, cold start:**
```
file → checksec → strings | grep flag → nm (stripped?) →
if packed: unpack (upx -d) → objdump -d skim for main →
open in Ghidra/r2, auto-analyze → trace main → find comparison/flag-construction logic
```

**Crackme / license-check style:**
```
Find the comparison (strcmp/memcmp/manual byte loop) → set breakpoint right after →
inspect register/stack for expected value → if input transformed (XOR/add loop),
reverse the transform manually or symbolic-exec with angr_template.py
```

**Binary refuses to run under debugger (anti-debug):**
```
strings for ptrace/IsDebuggerPresent → objdump around _start for early anti-debug calls →
patch out the check (r2 -w, wa nop) → re-run under debugger normally
```

**Packed/obfuscated binary:**
```
DIE (diec/die) for instant packer/compiler ID → try upx -d directly if UPX flagged →
if custom: break at entry, single-step past unpacking stub, dump memory →
analyze the dumped unpacked code as a fresh binary
```

**Non-C binary (Go/Rust/.NET/Java) shows up:**
```
file to confirm language/runtime → use language-specific decompiler (see section 6) →
Go/Rust: check if symbol names survived stripping (often do) →
.NET/Java: prefer GUI decompiler (dnSpy/jd-gui) over raw IL/bytecode reading
```

---
