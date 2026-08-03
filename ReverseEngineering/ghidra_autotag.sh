#!/usr/bin/env bash
# ghidra_autotag.sh -- Batch-analyze a binary with Ghidra headless and
# auto-tag/flag functions that call dangerous or interesting library
# functions (system, strcpy, gets, memcpy w/ unchecked size, etc), rather
# than needing to manually grep the full decompiled output like
# ghidra_headless_analyze.sh does. Adds a Ghidra bookmark + prints a ranked
# summary so you can jump straight to the functions worth reading first.
#
# Requires Ghidra installed; set GHIDRA_HOME below or export it in your shell.
#
# Usage: ./ghidra_autotag.sh <binary> [output_dir]

set -euo pipefail

GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
BINARY="$1"
OUTDIR="${2:-./ghidra_autotag_out}"
PROJECT_NAME="ctf_autotag_$$"

mkdir -p "$OUTDIR"

cat > "$OUTDIR/AutoTagSuspicious.java" << 'JAVA_EOF'
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Symbol;
import java.io.PrintWriter;
import java.util.*;

// Weight roughly reflects how likely a call is to be the "interesting"
// function in a CTF crackme -- e.g. strcmp/memcmp near program logic is a
// stronger signal than a routine printf, but every project's weighting is
// a heuristic, not ground truth. Read the actual decompiled context before
// trusting the ranking blindly.
public class AutoTagSuspicious extends GhidraScript {

    static final Map<String, Integer> WEIGHTS = new HashMap<>();
    static {
        WEIGHTS.put("system", 10);
        WEIGHTS.put("exec", 10);
        WEIGHTS.put("execve", 10);
        WEIGHTS.put("popen", 9);
        WEIGHTS.put("gets", 9);
        WEIGHTS.put("strcpy", 7);
        WEIGHTS.put("strcat", 7);
        WEIGHTS.put("sprintf", 6);
        WEIGHTS.put("memcpy", 5);
        WEIGHTS.put("strcmp", 8);
        WEIGHTS.put("strncmp", 8);
        WEIGHTS.put("memcmp", 8);
        WEIGHTS.put("scanf", 5);
        WEIGHTS.put("ptrace", 9);   // common anti-debug check
        WEIGHTS.put("fork", 4);
        WEIGHTS.put("mprotect", 6); // common in self-modifying/packed code
        WEIGHTS.put("srand", 5);
        WEIGHTS.put("rand", 4);
        WEIGHTS.put("xor", 5);      // matches inlined helper names, not libc, kept as a name-substring hint
    }

    @Override
    public void run() throws Exception {
        SymbolTable symTab = currentProgram.getSymbolTable();
        Map<Function, Integer> score = new HashMap<>();
        Map<Function, List<String>> hitsPerFunction = new HashMap<>();

        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isThunk() || f.isExternal()) continue;
            int total = 0;
            List<String> hits = new ArrayList<>();

            for (Instruction instr : currentProgram.getListing().getInstructions(f.getBody(), true)) {
                for (Reference ref : instr.getReferencesFrom()) {
                    if (ref.getReferenceType() != RefType.UNCONDITIONAL_CALL
                        && ref.getReferenceType() != RefType.CONDITIONAL_CALL) continue;
                    Address toAddr = ref.getToAddress();
                    Symbol sym = symTab.getPrimarySymbol(toAddr);
                    if (sym == null) continue;
                    String name = sym.getName().toLowerCase();
                    for (Map.Entry<String, Integer> w : WEIGHTS.entrySet()) {
                        if (name.contains(w.getKey())) {
                            total += w.getValue();
                            hits.add(sym.getName() + " @ " + instr.getAddress());
                        }
                    }
                }
            }
            if (total > 0) {
                score.put(f, total);
                hitsPerFunction.put(f, hits);
                // Bookmark it in the Ghidra project so it's visible in the GUI too
                createBookmark(f.getEntryPoint(), "AutoTag", "score=" + total + " " + f.getName());
            }
        }

        List<Function> ranked = new ArrayList<>(score.keySet());
        ranked.sort((a, b) -> score.get(b) - score.get(a));

        PrintWriter out = new PrintWriter(getScriptArgs()[0]);
        out.println("# Ranked suspicious-function report (higher score = look here first)");
        out.println("# Weighting is a heuristic -- verify against actual decompiled logic.\n");
        for (Function f : ranked) {
            out.println("Score " + score.get(f) + "  " + f.getName() + " @ " + f.getEntryPoint());
            for (String h : hitsPerFunction.get(f)) {
                out.println("    -> " + h);
            }
        }
        out.close();
    }
}
JAVA_EOF

"$GHIDRA_HOME/support/analyzeHeadless" \
    "$OUTDIR" "$PROJECT_NAME" \
    -import "$BINARY" \
    -postScript AutoTagSuspicious.java "$OUTDIR/suspicious_functions.txt" \
    -scriptPath "$OUTDIR" \
    -deleteProject

echo "[+] Ranked suspicious-function report: $OUTDIR/suspicious_functions.txt"
echo "    Bookmarks were also added inside the Ghidra project for GUI browsing"
echo "    (re-import $BINARY into a persistent project, not -deleteProject, if you want to keep them)."
echo "    Pair with ghidra_headless_analyze.sh's decompiled_functions.c for full source context."
