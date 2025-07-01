//This script is meant to automate the usage of temporary FIDBs, allows you to use multiple BSim databases per file to recover functions, use file metadata recovery scripts (Golang or Nim, for example), and allows you to use a LLM to further annotate the code. Next, the script adds some graphical elements by colourising complex function calls as dark red while non-complex functions are marked as light red. 
//@author Max 'Libra' Kersten for Trellix
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;

public class Automagic extends GhidraScript {

	/**
	 * The Function ID analyzer name, taken from Ghidra's source code
	 */
	private static final String FUNCTION_ID_ANALYZER = "Function ID";

	/**
	 * The auto analysis manager within Ghidra, used to check if one or more
	 * analyzers are still running
	 */
	private AutoAnalysisManager autoAnalysisManager;

	/**
	 * The Function ID database file manager
	 */
	private FidFileManager fidFileManager;

	@Override
	protected void run() throws Exception {
		/*
		 * Initialise variables which are used in functions later on
		 */
		autoAnalysisManager = AutoAnalysisManager.getAnalysisManager(currentProgram);
		fidFileManager = FidFileManager.getInstance();

		/*
		 * Obtain all required arguments for all scripts
		 */

		/*
		 * Example CLI input for this script:
		 * 
		 * [true/false if extra fidb databases should be used] [path/to/fidb/files]
		 * [true/false if bsim renaming should be used] [path/to/bsim.config]
		 * [true/false if an LLM should be used to rename information] [LLM AI API URL]
		 * [true/false to decide if functions need to be renamed] [true/false to decide
		 * if variables need to be renamed]
		 */
		boolean useFidb = askYesNo("Additional FIDB files", "Use additional FIDB files?");
		String fidFolderPath = askString("Location of additional FIDBs",
				"What is the folder where the additional FIDB files are located?");
		boolean useBSimRenamer = askYesNo("Use BSim?", "Use BSim to rename matches?");
		String bsimConfigPath = askString("BSim configuration file location",
				"What is the location of the BSim configuration file?");
		boolean useGhidrAI = askYesNo("GhidrAI LLM usage",
				"Use the GhidrAI script to rename functions, variables, and summarise functions?");
		String ghidraiApiUrl = askString("GhidrAI LLM API endpoint", "What is the API URL of the LLM?");
		boolean ghidraiRenameFunctions = askYesNo("Rename functions", "Rename functions based on AI suggestions?");
		boolean ghidraiRenameVariables = askYesNo("Rename variables", "Rename variables based on AI suggestions?");

		/*
		 * End of obtaining arguments for all scripts
		 */

		/*
		 * Test the validity of all script arguments, prior to making changes to the
		 * current program. Values asked via the askValues (or specific ask* functions)
		 * cannot be null, so there is no need to check for the null-state.
		 */

		File fidFolder = new File(fidFolderPath);
		if (useFidb) {
			// Check if the FID folder exists
			if (fidFolder.exists() == false) {
				throw new IOException("The provided FIDB folder does not exist: " + fidFolder.getAbsolutePath());
			}

			/*
			 * Check if the provided existing path is a folder by throwing an exception if
			 * it is a file
			 */
			if (fidFolder.isFile()) {
				throw new IOException("The provided FIDB folder is a file: " + fidFolder.getAbsolutePath());
			}
		}

		List<BSimExecutionConfig> configs = null;
		if (useBSimRenamer) {
			File bsimConfigFile = new File(bsimConfigPath);

			// Check if the BSim config file exists
			if (bsimConfigFile.exists() == false) {
				throw new IOException("The provided BSim file does not exist: " + bsimConfigPath);
			}

			/*
			 * Check if the provided existing path is a file by throwing an exception if it
			 * is a folder
			 */
			if (bsimConfigFile.isDirectory()) {
				throw new IOException("The provided BSim path is a directory: " + bsimConfigPath);
			}

			// Parse all configs from the existing BSim config file
			configs = parseBSimExecutionConfigs(bsimConfigFile);
		}

		/*
		 * Metadata analysis is the closest ground truth that is available from the
		 * lossy compilation process. Recovering names from Golang's pclntab and
		 * demangling Nim function names are included, but any type of metadata related
		 * script should be put in this section.
		 */

		/*
		 * Recover function names, types, and strings (both dynamic and static), based
		 * on the pclntab. More information can be found here:
		 * https://www.trellix.com/blogs/research/feeding-gophers-to-ghidra/
		 */
		runScriptAndWait("GolangRecovery", false);

		/*
		 * Demangle Nim function names and recover Nim strings, made by ESET's Alexandre
		 * Côté Cyr. More information on ESET's blog:
		 * https://www.welivesecurity.com/en/eset-research/introducing-nimfilt-reverse-
		 * engineering-tool-nim-compiled-binaries/
		 * 
		 * The GitHub repository with the scripts: https://github.com/eset/nimfilt
		 */
		runScriptAndWait("NimFilt", false);

		/*
		 * Load and activate all FID databases from a given folder. All newly loaded and
		 * activated FID databases are returned in a list, allowing for easy removal
		 * from the attached FID databases list later on.
		 */
		List<FidFile> additionalFids = loadAdditionalFunctionIdDatabases(fidFolder);

		// Apply FunctionID signatures from the loaded FID databases
		runAnalyzer(FUNCTION_ID_ANALYZER);

		// Run the BSim rename script for all given and previously parsed configs
		if (useBSimRenamer) {
			runBSimRenamer(configs);
		}

		// Run the GhidrAI rename and summary script
		if (useGhidrAI) {
			runGhidrAI(ghidraiApiUrl, ghidraiRenameFunctions, ghidraiRenameVariables);
		}

		/*
		 * Propagate the parameters for external functions. This is done by running
		 * Ghidra's Propagatex86ExternalParams for 32-bit programs. For 64-bit programs,
		 * the variant of Karsten Hahn (aka struppigel) is used (originally found at
		 * https://github.com/struppigel/hedgehog-tools/blob/main/ghidra_scripts/
		 * PropagateExternalParametersX64.java)
		 * 
		 * The function to get the bitness returns -1 if an error is found, which is why
		 * the if- and else-if-clauses are set to a specific number without the usage of
		 * an else-clause.
		 */
		int bitness = getBitness();
		if (bitness == 32) {
			runScriptAndWait("PropagateExternalParametersScript", false);
		} else if (bitness == 64) {
			runScriptAndWait("PropagateExternalParametersX64", false);
		}

		/*
		 * Colour function call instructions based on the complexity depth level of the
		 * called function
		 */
		runScriptAndWait("ColouriseByComplexity", false);

		// Restore original FID database selection
		restoreOriginalFunctionIdDatabaseSelection(additionalFids);
	}

	/**
	 * Prints the given message via the
	 * {@link ghidra.app.script.GhidraScript#println(String)} method, depending on
	 * the running mode and boolean.
	 * 
	 * @param message       the message to print
	 * @param printHeadless true if the message should be printed when executing
	 *                      headless, false if not
	 */
	private void log(String message, boolean printHeadless) {
		if (SystemUtilities.isInHeadlessMode()) {
			if (printHeadless == false) {
				return;
			}
		}
		println(message);
	}

	/**
	 * A wrapper for {@link #runScriptAndWait(String, String[], boolean)} to run a
	 * script without any arguments
	 * 
	 * @param scriptName      the name of the script
	 * @param throwExceptions if the execution of the script should throw
	 *                        encountered exceptions, or if they should be caught
	 * @throws Exception the exception which is thrown if the second argument is
	 *                   true
	 */
	private void runScriptAndWait(String scriptName, boolean throwExceptions) throws Exception {
		runScriptAndWait(scriptName, null, throwExceptions);
	}

	/**
	 * Runs a script and waits until its execution is complete
	 * 
	 * @param scriptName      the name of the script
	 * @param scriptArguments arguments for the script, may be <code>null</code>
	 * @param throwExceptions if the execution of the script should throw
	 *                        encountered exceptions, or if they should be caught
	 * @throws Exception
	 */
	private void runScriptAndWait(String scriptName, String[] scriptArguments, boolean throwExceptions)
			throws Exception {
		try {
			log("Running " + scriptName, true);
			runScript(scriptName, scriptArguments, getState());
			waitUntilAutoAnalysisCompletes();
			log("Finished " + scriptName, true);
		} catch (Exception ex) {
			if (throwExceptions) {
				throw ex;
			}
			printerr(ex.toString());
		}
	}

	/**
	 * Run an analyzer based on its name
	 * 
	 * @param analyzerName the name of the analyzer to run
	 * @throws InterruptedException
	 * @throws CancelledException
	 */
	private void runAnalyzer(String analyzerName) throws InterruptedException, CancelledException {
		Analyzer analyzer = autoAnalysisManager.getAnalyzer(analyzerName);
		autoAnalysisManager.scheduleOneTimeAnalysis(analyzer, currentProgram.getAddressFactory().getAddressSet());
		waitUntilAutoAnalysisCompletes();
	}

	/**
	 * Wait until no analyzers are running anymore
	 * 
	 * @throws InterruptedException
	 * @throws CancelledException
	 */
	private void waitUntilAutoAnalysisCompletes() throws InterruptedException, CancelledException {
		while (autoAnalysisManager.isAnalyzing()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			Thread.sleep(1000); // Sleep to avoid consuming extra CPU cycles in-between checks
		}
	}

	private void runGhidrAI(String apiUrl, boolean renameFunctions, boolean renameVariables) throws Exception {
		/*
		 * Required information to run GhidrAI:
		 * 
		 * - AI API URL
		 * 
		 * - Rename function based on suggestion: yes/no
		 * 
		 * - Rename variables based on suggestions: yes/no
		 */
		String[] ghidraiArgs = new String[3];
		ghidraiArgs[0] = apiUrl; // AI API URL
		ghidraiArgs[1] = "" + renameFunctions; // suggest function name
		ghidraiArgs[2] = "" + renameVariables; // rename based on suggestion
		runScriptAndWait("GhidrAI", ghidraiArgs, false);
	}

	private String replaceLastOccurrence(String original, String target, String replacement) {
		int lastIndex = original.lastIndexOf(target);
		if (lastIndex == -1) {
			return original; // Target string not found
		}
		String beforeLastOccurrence = original.substring(0, lastIndex);
		String afterLastOccurrence = original.substring(lastIndex + target.length());
		return beforeLastOccurrence + replacement + afterLastOccurrence;
	}

	private List<BSimExecutionConfig> parseBSimExecutionConfigs(File file) throws IOException {
		List<BSimExecutionConfig> configs = new ArrayList<>();
		int nonParsableLines = 0;

		List<String> lines = new ArrayList<>();
		try {
			lines = Files.readAllLines(file.toPath());
		} catch (IOException ex) {
			printerr("Failed to read the file with the referenced BSim files: " + file.getAbsolutePath());
			throw ex;
		}

		if (lines.isEmpty()) {
			throw new IOException("No lines present in the BSim config file!");
		}

		for (String line : lines) {
			if (line.startsWith("#")) {
				nonParsableLines++;
				continue;
			}
			int errorCount = 0;
			println("Parsing the following BSim config file line: " + line);

			String[] split = line.split(",");
			if (split.length < 6 || split.length > 7) {
				printerr(
						"Not all data is present within the given line, the length should be 6 or 7, whereas the length of this line is only "
								+ split.length);
				errorCount++;
			}

			String databaseUrl = split[0];
			if (databaseUrl.endsWith(".mv.db")) {
				databaseUrl = replaceLastOccurrence(databaseUrl, ".mv.db", "");
				println("Removed the .mv.db extension from the database file path: " + databaseUrl);
			}
			File database = new File(databaseUrl + ".mv.db");
			if (database.exists() == false) {
				printerr("The provided database does not exist: " + databaseUrl);
				errorCount++;
			}
			if (database.isDirectory()) {
				printerr("The provided database url is a folder: " + databaseUrl);
				errorCount++;
			}

			double lowerSimilartyBound = -1;
			try {
				lowerSimilartyBound = Double.parseDouble(split[1]);
			} catch (Exception ex) {
				printerr("The lower similarity bound is not a double: " + split[1]);
				errorCount++;
			}

			int maximumNumberOfMatches = -1;
			try {
				maximumNumberOfMatches = Integer.parseInt(split[2]);
			} catch (Exception ex) {
				printerr("The maximum number of matches is not an integer: " + split[2]);
				errorCount++;
			}

			/*
			 * Booleans parsed by Boolean.parseBoolean (and similar functions) return true
			 * for any spelling of true, and return false for anything else. This is not the
			 * check we want here, as we want to have either true or false as a value,
			 * anything else is incorrect. Thus, testing of the literal string value is what
			 * we need.
			 */
			String renameSingleMatchesString = split[3];
			boolean renameSingleMatches = false;
			if (renameSingleMatchesString.equalsIgnoreCase("true")) {
				renameSingleMatches = true;
			} else if (renameSingleMatchesString.equalsIgnoreCase("false")) {
				renameSingleMatches = false;
			} else {
				printerr("The boolean value to define if single matches should be renamed is neither true nor false: "
						+ renameSingleMatches);
				errorCount++;
			}

			String renameMultiMatchesString = split[4];
			boolean renameMultiMatches = false;
			if (renameMultiMatchesString.equalsIgnoreCase("true")) {
				renameMultiMatches = true;
			} else if (renameMultiMatchesString.equalsIgnoreCase("false")) {
				renameMultiMatches = false;
			} else {
				printerr("The boolean value to define if multi-matches should be renamed is neither true nor false: "
						+ renameMultiMatchesString);
				errorCount++;
			}

			String renameGenericMatchesString = split[5];
			boolean renameGenericMatches = false;
			if (renameGenericMatchesString.equalsIgnoreCase("true")) {
				renameGenericMatches = true;
			} else if (renameGenericMatchesString.equalsIgnoreCase("false")) {
				renameGenericMatches = false;
			} else {
				printerr("The boolean value to define if generic matches should be renamed is neither true nor false: "
						+ renameGenericMatchesString);
				errorCount++;
			}

			String customPrefix = null;
			if (split.length == 7) {
				customPrefix = split[6];
				if (customPrefix == null || customPrefix.isBlank()) {
					printerr("The required custom prefix has not been provided or is left blank while it is needed!");
					errorCount++;
				}
			}

			/*
			 * Required arguments, in order, split by a comma, should be:
			 * 
			 * - database URL, without any of the file extensions (the H2 database has two,
			 * neither should be included)
			 * 
			 * - the lower similarity bound between 0 and 1, as a double (i.e. 0.7)
			 * 
			 * - the maximum number of BSim matches per local function (i.e. 20)
			 * 
			 * - a boolean (true or false) which decides if single matches should be renamed
			 * 
			 * - a boolean (true or false) which decides if multi-matches should be renamed
			 * 
			 * - a boolean (true or false) which decides if generic matches should be
			 * renamed (if true, a 7th argument is required, otherwise it isn't)
			 * 
			 * - a String which is the prefix used when renaming generic matches
			 */

			// If there are no errors, this value should be zero
			if (errorCount == 0) {
				// Create the custom object
				BSimExecutionConfig config = new BSimExecutionConfig(databaseUrl, lowerSimilartyBound,
						maximumNumberOfMatches, renameSingleMatches, renameMultiMatches, renameGenericMatches,
						customPrefix);
				// Add the config to the list
				configs.add(config);
				// Notify the analyst
				println("Created the config object!");
			} else {
				// Print the error
				printerr("The config hasn't been parsed!");
			}
		}

		// Check if all lines have been parsed
		if ((configs.size() + nonParsableLines) == lines.size()) {
			// All lines have been parsed successfully
			return configs;
		}
		// If this is not the case, there were errors
		throw new IOException("Not all BSim configs were parsed correctly!");
	}

	private void runBSimRenamer(List<BSimExecutionConfig> configs) throws Exception {
		for (BSimExecutionConfig config : configs) {
			/*
			 * If the database does not match the current program, it is not to be used.
			 * There wont be (valid) results for the current program, and will only consume
			 * a lot of time. Using a large H2 database is never fast, but can be terribly
			 * slow if it is really large. A high(er) number of maximum matches will also
			 * increase the runtime.
			 * 
			 * This method is based on the naming scheme of the H2 databases that are
			 * linked, which is not the easiest approach, but works well as a best-effort
			 * method.
			 */
			if (bsimDatabaseMatches(config.getDatabaseUrl()) == false) {
				continue;
			}

			int size = 6;
			if (config.getPrefix() != null) {
				size = 7;
			}
			String[] bsimFunctionRenamerArgs = new String[size];
			bsimFunctionRenamerArgs[0] = config.getDatabaseUrl(); // database URL
			bsimFunctionRenamerArgs[1] = "" + config.getLowerSimilarityBound(); // lower similarity bound
			bsimFunctionRenamerArgs[2] = "" + config.getMaximumMatches(); // maximum bsim matches per local function
			bsimFunctionRenamerArgs[3] = "" + config.renameSingleMatches(); // rename single matches
			bsimFunctionRenamerArgs[4] = "" + config.renameMultiMatches(); // rename multi-matches
			bsimFunctionRenamerArgs[5] = "" + config.renameGenericMatches(); // rename generic matches
			if (size == 7) {
				bsimFunctionRenamerArgs[6] = config.getPrefix(); // the custom prefix to use
			}

			runScriptAndWait("BsimFunctionRenamer", bsimFunctionRenamerArgs, false);
		}
	}

	private boolean bsimDatabaseMatches(String databaseUrl) {
		/*
		 * TODO handle bsim files based on their file name, automatically excluding
		 * architectures which are incorrect for the given file, thus saving a lot of
		 * time when dealing with large H2 databases.
		 * 
		 * This can be done by running some extra checks:
		 * 
		 * -Check the language ID of the BSim database and the current program (keep in
		 * mind that "medium nosize" allows 32-bit and 64-bit signatures to
		 * mix-and-match
		 * 
		 * C:\Users\malwa\Desktop\bsim-signatures\bsim.rust.windows.x86_64.h2.medium-
		 * nosize
		 */

		/*
		 * Assume the database is a file which exists, as this check has been performed
		 * before
		 */
		File databaseUrlFile = new File(databaseUrl);
		BsimFileNameContainer container = convertIntoContainer(databaseUrlFile.getName());
		// Container is null if the file name format does not match
		if (container == null) {
			return true;
		}

		String executableFormat = currentProgram.getExecutableFormat(); // i.e. Portable Executable (PE)
		String cspec = currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString(); // i.e. windows
		String languageId = currentProgram.getLanguage().getLanguageID().getIdAsString(); // i.e. x86:LE:32:default

		if (container.getPlatform().equalsIgnoreCase("windows")) {
			if (executableFormat.equalsIgnoreCase("Portable Executable (PE)")
					|| cspec.equalsIgnoreCase(container.getPlatform())) {
				// Matches, continue onwards
			}
		} else if (container.getPlatform().equalsIgnoreCase("linux")) {
			if (executableFormat.equalsIgnoreCase("Executable and Linking Format (ELF)")
					|| cspec.equalsIgnoreCase(container.getPlatform())) {
				// Matches, continue onwards
			}
		} else if (container.getPlatform().equalsIgnoreCase("apple")
				|| container.getPlatform().equalsIgnoreCase("macos")) {
			if (executableFormat.equalsIgnoreCase("Mac OS X Mach-O")
					|| cspec.equalsIgnoreCase(container.getPlatform())) {
				// Matches, continue onwards
			}
		}

		String[] languageIdSplit = languageId.split(":");
		if (languageIdSplit.length == 4) {
			// TODO get uniform check for the language ID
			/*
			 * TODO ensure that the databaseSize cases with "medium-nosize" includes cross
			 * architecture options as 32-bits and 64-bits signatures are used
			 * interchangeably (to a certain extend)
			 */
			String architecture = languageIdSplit[0] + languageIdSplit[2];
		} else {
			// Cannot confirm the type, but it should have a length of 4: x86:LE:32:default
		}

		// TODO update the return value once the function is complete
		return true;
	}

	private BsimFileNameContainer convertIntoContainer(String fileName) {
		String[] split = fileName.split("\\.");
		if (split.length == 6) {
			String bsim = split[0];
			String library = split[1];
			String platform = split[2];
			String architecture = split[3];
			String databaseType = split[4];
			String databaseSize = split[5];
			return new BsimFileNameContainer(bsim, library, platform, architecture, databaseType, databaseSize);
		}
		return null;
	}

	class BsimFileNameContainer {
		private String bsim;
		private String library;
		private String platform;
		private String architecture;
		private String databaseType;
		private String databaseSize;

		public BsimFileNameContainer(String bsim, String library, String platform, String architecture,
				String databaseType, String databaseSize) {
			super();
			this.bsim = bsim;
			this.library = library;
			this.platform = platform;
			this.architecture = architecture;
			this.databaseType = databaseType;
			this.databaseSize = databaseSize;
		}

		public String getBsim() {
			return bsim;
		}

		public String getLibrary() {
			return library;
		}

		public String getPlatform() {
			return platform;
		}

		public String getArchitecture() {
			return architecture;
		}

		public String getDatabaseType() {
			return databaseType;
		}

		public String getDatabaseSize() {
			return databaseSize;
		}
	}

	/**
	 * Loads all files ending with .FIDB from the givne folder
	 * 
	 * @param folder the folder to load the function ID files from
	 * @return a list of loaded FID files
	 */
	private List<FidFile> loadAdditionalFunctionIdDatabases(File folder) {
		List<FidFile> fids = new ArrayList<>();

		for (File file : folder.listFiles()) {
			if (file.isFile() == false) {
				continue;
			}

			if (file.getName().endsWith(".fidb")) {
				int size = fidFileManager.getFidFiles().size();
				FidFile fidFile = fidFileManager.addUserFidFile(file);
				if (fidFile != null) {
					fidFile.setActive(true);
					/*
					 * Adding a valid FIDB file is always possible, even if its already known to
					 * Ghidra. Thus, a check is added to see if the total number of FIDB files has
					 * increased. If it was already known, this is not the case. If it wasn't, then
					 * it is. To avoid removing a FIDB from the already known FIDB list, the FIDB
					 * file will only be added to the list if Ghidra added a new FIDB to its known
					 * list.
					 */
					if (fidFileManager.getFidFiles().size() > size) {
						fids.add(fidFile);
						println("Added \"" + fidFile.getName() + "\" to the active loaded FunctionID databases!");
					}
				}
			}
		}

		return fids;
	}

	/**
	 * Restore the original FIDB selection. This unloads the previously loaded FIDBs
	 * @param extraFunctionIdDatabases the list of previously loaded FID files
	 */
	private void restoreOriginalFunctionIdDatabaseSelection(List<FidFile> extraFunctionIdDatabases) {
		for (FidFile fidFile : extraFunctionIdDatabases) {
			fidFileManager.removeUserFile(fidFile);
			println("Removed \"" + fidFile.getName() + "\" from the loaded FunctionID databases!");
		}
	}

	/**
	 * Gets the program's bitness
	 * 
	 * @return the bitness as an integer, or -1 if an error occurs
	 */
	private int getBitness() {
		Map<String, String> mapping = currentProgram.getMetadata();
		String bitness = mapping.get("Address Size");
		try {
			return Integer.parseInt(bitness);
		} catch (Exception ex) {
			printerr(ex.toString());
			return -1;
		}
	}

	class BSimExecutionConfig {
		private String databaseUrl;
		private double lowerSimilarityBound;
		private int maximumMatches;
		private boolean renameSingleMatches;
		private boolean renameMultiMatches;
		private boolean renameGenericMatches;
		private String prefix;

		public BSimExecutionConfig(String databaseUrl, double lowerSimilarityBound, int maximumMatches,
				boolean renameSingleMatches, boolean renameMultiMatches, boolean renameGenericMatches, String prefix) {
			this.databaseUrl = databaseUrl;
			this.lowerSimilarityBound = lowerSimilarityBound;
			this.maximumMatches = maximumMatches;
			this.renameSingleMatches = renameSingleMatches;
			this.renameMultiMatches = renameMultiMatches;
			this.renameGenericMatches = renameGenericMatches;
			this.prefix = prefix;
		}

		public String getDatabaseUrl() {
			return databaseUrl;
		}

		public void setDatabaseUrl(String databaseUrl) {
			this.databaseUrl = databaseUrl;
		}

		public double getLowerSimilarityBound() {
			return lowerSimilarityBound;
		}

		public void setLowerSimilarityBound(double lowerSimilarityBound) {
			this.lowerSimilarityBound = lowerSimilarityBound;
		}

		public int getMaximumMatches() {
			return maximumMatches;
		}

		public void setMaximumMatches(int maximumMatches) {
			this.maximumMatches = maximumMatches;
		}

		public boolean renameSingleMatches() {
			return renameSingleMatches;
		}

		public void setRenameSingleMatches(boolean renameSingleMatches) {
			this.renameSingleMatches = renameSingleMatches;
		}

		public boolean renameMultiMatches() {
			return renameMultiMatches;
		}

		public void setRenameMultiMatches(boolean renameMultiMatches) {
			this.renameMultiMatches = renameMultiMatches;
		}

		public boolean renameGenericMatches() {
			return renameGenericMatches;
		}

		public void setRenameGenericMatches(boolean renameGenericMatches) {
			this.renameGenericMatches = renameGenericMatches;
		}

		public String getPrefix() {
			return prefix;
		}

		public void setPrefix(String prefix) {
			this.prefix = prefix;
		}
	}
}