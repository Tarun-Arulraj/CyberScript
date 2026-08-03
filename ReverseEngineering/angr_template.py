#!/usr/bin/env python3
"""
angr_template.py -- Generic angr symbolic execution template for "find the
right input" reversing challenges (license-key checkers, crackmes, etc).

Requires: pip install angr

Customize:
  - BINARY path
  - avoid/find addresses (get these from Ghidra/objdump: addresses of
    "Wrong password" / "Access denied" vs "Correct!" / "Access granted")
  - input length / stdin vs argv vs scanf format
"""
import angr
import claripy
import sys

BINARY = "./chall"          # <-- path to target binary
INPUT_LEN = 20              # <-- guess or determine from binary logic

# --- Addresses to steer exploration (fill these in from static analysis) ---
FIND_ADDR = 0x00401234       # address reached only on "success" path
AVOID_ADDRS = [0x00401300]   # addresses on "failure" paths (e.g. puts("Wrong!"))


def make_symbolic_stdin_project(binary_path, input_len):
    proj = angr.Project(binary_path, auto_load_libs=False)

    flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(input_len)]
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b"\n")])

    state = proj.factory.full_init_state(
        stdin=angr.SimFileStream(name='stdin', content=flag, has_end=False),
    )

    # Constrain to printable ASCII to speed up solving and get readable flags
    for c in flag_chars:
        state.solver.add(c >= 0x20)
        state.solver.add(c <= 0x7e)

    return proj, state, flag


def solve_stdin_challenge():
    proj, state, flag = make_symbolic_stdin_project(BINARY, INPUT_LEN)
    simgr = proj.factory.simgr(state)

    print("[*] Exploring ... (this can take a while, add more avoid addrs if it hangs)")
    simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDRS)

    if simgr.found:
        found_state = simgr.found[0]
        result = found_state.solver.eval(flag, cast_to=bytes)
        print("[+] Found input:", result)
        return result
    else:
        print("[-] No path to FIND_ADDR found. Adjust addresses or input length.")
        return None


def make_symbolic_argv_project(binary_path, input_len):
    """Variant for challenges that take input as argv[1] instead of stdin."""
    proj = angr.Project(binary_path, auto_load_libs=False)
    arg1 = claripy.BVS("arg1", input_len * 8)
    state = proj.factory.entry_state(args=[binary_path, arg1])
    for byte in arg1.chop(8):
        state.solver.add(byte >= 0x20)
        state.solver.add(byte <= 0x7e)
    return proj, state, arg1


def solve_argv_challenge():
    proj, state, arg1 = make_symbolic_argv_project(BINARY, INPUT_LEN)
    simgr = proj.factory.simgr(state)
    simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDRS)
    if simgr.found:
        found_state = simgr.found[0]
        print("[+] Found arg:", found_state.solver.eval(arg1, cast_to=bytes))
    else:
        print("[-] No solution found")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "stdin"
    if mode == "argv":
        solve_argv_challenge()
    else:
        solve_stdin_challenge()
