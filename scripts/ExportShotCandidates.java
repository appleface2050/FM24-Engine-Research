// FM24 局部静态取证：只反汇编指定函数，不执行游戏，不进行全量自动分析。
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import java.nio.file.*;

public class ExportShotCandidates extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long started = System.currentTimeMillis();
        println("ExportShotCandidates input=" + currentProgram.getName()
            + " output=" + args[0] + " targets=" + (args.length - 1));
        StringBuilder out = new StringBuilder();
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        int success = 0;
        try {
            for (int index = 1; index < args.length; index++) {
                String[] range = args[index].split(":");
                Address address = toAddr(range[0]);
                AddressSet boundary = range.length == 2
                    ? new AddressSet(address, toAddr(range[1]).subtract(1)) : null;
                println("START " + address + " elapsed_ms="
                    + (System.currentTimeMillis() - started));
                out.append("\nFUNCTION ").append(address).append("\n");
                new DisassembleCommand(address, boundary, true).applyTo(currentProgram);
                Function function = getFunctionAt(address);
                if (function == null) {
                    new CreateFunctionCmd(address).applyTo(currentProgram);
                    function = getFunctionAt(address);
                }
                if (function == null) {
                    out.append("NO FUNCTION\n");
                    println("SKIP " + address);
                    continue;
                }
                if (boundary != null) {
                    function.setBody(boundary);
                }
                DecompileResults result = dec.decompileFunction(function, 60, monitor);
                out.append("BODY ").append(function.getBody()).append("\n");
                if (result.decompileCompleted()) {
                    out.append(result.getDecompiledFunction().getC());
                    success++;
                } else {
                    out.append("FAILED: ").append(result.getErrorMessage()).append("\n");
                }
                out.append("\nLISTING INSTRUCTIONS (bounded recursive disassembly)\n");
                InstructionIterator instructions = currentProgram.getListing()
                    .getInstructions(function.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    out.append(instruction.getAddress()).append(" ")
                        .append(instruction.toString()).append("\n");
                }
                Files.writeString(Path.of(args[0]), out.toString());
                println("END " + address + " complete=" + result.decompileCompleted()
                    + " elapsed_ms=" + (System.currentTimeMillis() - started));
            }
            Files.writeString(Path.of(args[0]), out.toString());
            println("DONE success=" + success + " targets=" + (args.length - 1)
                + " elapsed_ms=" + (System.currentTimeMillis() - started));
        } finally {
            dec.dispose();
        }
    }
}
