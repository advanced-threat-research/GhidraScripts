//Runs all four Golang analysis scripts, based on their names. If no such script is found, an error is printed and the next script is executed.
//@author Max 'Libra' Kersten of Trellix' Advanced Research Center
//@category Golang
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;

public class GolangRecovery extends GhidraScript {

	@Override
	protected void run() throws Exception {
		runScript("GolangFunctionRecovery");
		runScript("GolangStaticStringRecovery");
		runScript("GolangDynamicStringRecovery");
		runScript("GolangTypeRecovery");
	}
}
