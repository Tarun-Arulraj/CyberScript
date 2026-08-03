#!/usr/bin/env bash
# ghidra_headless_analyze.sh -- Batch decompile a binary with Ghidra headless
# and dump all function decompilations to a text file for grepping / reading
# without opening the GUI. Useful for quick triage of a rev challenge.
#
# Requires Ghidra installed; set GHIDRA_HOME below or export it in your shell.
#
# Usage: ./ghidra_headless_analyze.sh <binary> [output_dir]

set -euo pipefail

GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
BINARY="$1"
OUTDIR="${2:-./ghidra_out}"
PROJECT_NAME="ctf_analysis_$$"

mkdir -p "$OUTDIR"

# Post-analysis script that dumps decompiled C for every function
cat > "$OUTDIR/DumpDecompiled.java" << 'JAVA_EOF'
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class DumpDecompiled extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        PrintWriter out = new PrintWriter(getScriptArgs()[0]);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            DecompileResults res = decomp.decompileFunction(f, 60, monitor);
            if (res.decompileCompleted()) {
                out.println("// ---- " + f.getName() + " @ " + f.getEntryPoint() + " ----");
                out.println(res.getDecompiledFunction().getC());
                out.println();
            }
        }
        out.close();
    }
}
JAVA_EOF

"$GHIDRA_HOME/support/analyzeHeadless" \
    "$OUTDIR" "$PROJECT_NAME" \
    -import "$BINARY" \
    -postScript DumpDecompiled.java "$OUTDIR/decompiled_functions.c" \
    -scriptPath "$OUTDIR" \
    -deleteProject

echo "[+] Decompiled functions written to: $OUTDIR/decompiled_functions.c"
echo "    grep for interesting stuff, e.g.:"
echo "    grep -n -iE 'flag|strcmp|password|xor|check' $OUTDIR/decompiled_functions.c"
