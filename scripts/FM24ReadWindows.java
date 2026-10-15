import ghidra.app.script.GhidraScript;
import java.nio.file.*;
public class FM24ReadWindows extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        StringBuilder out = new StringBuilder();
        for (int i=1; i<args.length; i++) {
            byte[] bytes = new byte[96];
            currentProgram.getMemory().getBytes(toAddr(args[i]), bytes);
            out.append(args[i]).append(" ");
            for (byte b : bytes) out.append(String.format("%02x", b & 255));
            out.append("\n");
        }
        Files.writeString(Path.of(args[0]), out.toString());
        println("Read " + (args.length-1) + " static windows");
    }
}
