
//A script to headlessly create FIDB files based on all programs within the given project. Based on "CreateMultipleLibraries.java" by the Ghidra team, inspired by Threatrack's work (https://blog.threatrack.de/2019/09/20/ghidra-fid-generator/)
//@author Max 'Libra' Kersten for Trellix
//@category FunctionID
//@keybinding
//@menupath
//@toolbar
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.db.LibraryRecord;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidPopulateResult.Disposition;
import ghidra.feature.fid.service.FidPopulateResultReporter;
import ghidra.feature.fid.service.FidService;
import ghidra.feature.fid.service.Location;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class AutomaticallyCreateFunctionIdDatabases extends GhidraScript {

	/**
	 * The Function ID service to be used
	 */
	private FidService fidService;

	/**
	 * The path to the log file where all logs are written (appended) to
	 */
	private Path logFile;

	/**
	 * Logs a message to Ghidra's console and to the log file in the specified
	 * output folder
	 * 
	 * @param message the message to print and write
	 */
	private void log(String message, boolean isError) {
		/*
		 * Write the (error) message to Ghidra's console, depending on the given boolean
		 */
		if (isError) {
			printerr(message);
		} else {
			println(message);
		}

		/*
		 * Try to append data to the log file
		 */
		try {
			// Append the error tag if the message is an error
			if (isError) {
				message = "ERROR: " + message;
			}
			// Append a newline to the message
			message += "\n";
			// Write the data to the log file
			Files.write(logFile, message.getBytes(), StandardOpenOption.APPEND);
		} catch (IOException e) {
			// Ignore exceptions, the console log already contains the logged information
		}
	}

	/**
	 * The reporter class, which implements the required Ghidra report class
	 */
	class FidReporter implements FidPopulateResultReporter {
		@Override
		public void report(FidPopulateResult result) {
			// Check if a result is given, if not, simply return
			if (result == null) {
				return;
			}

			// Get the library record from the result
			LibraryRecord libraryRecord = result.getLibraryRecord();

			// Get the library family name, version, and variant
			String libraryFamilyName = libraryRecord.getLibraryFamilyName();
			String libraryVersion = libraryRecord.getLibraryVersion();
			String libraryVariant = libraryRecord.getLibraryVariant();

			// Log the obtained information
			log(libraryFamilyName + ':' + libraryVersion + ':' + libraryVariant, false);

			// Log the attempted, added, and excluded count for the generated FIDB
			log(result.getTotalAttempted() + " total functions visited", false);
			log(result.getTotalAdded() + " total functions added", false);
			log(result.getTotalExcluded() + " total functions excluded", false);

			// Log all exclusions
			log("Breakdown of exclusions:", false);
			for (Entry<Disposition, Integer> entry : result.getFailures().entrySet()) {
				if (entry.getKey() != Disposition.INCLUDED) {
					log("    " + entry.getKey() + ": " + entry.getValue(), false);
				}
			}
			// Log all unresolved symbols
			log("List of unresolved symbols:", false);
			TreeSet<String> symbols = new TreeSet<>();
			for (Location location : result.getUnresolvedSymbols()) {
				symbols.add(location.getFunctionName());
			}
			for (String symbol : symbols) {
				log("    " + symbol, false);
			}
		}
	}

	/**
	 * Parses the symbols within the given file, reading it line-by-line where each
	 * line is assumed to be a symbol
	 * 
	 * @param commonSymbolsFile the file to read
	 * @return a list of symbols to exclude when making FunctionID signatures
	 * @throws IOException
	 * @throws CancelledException
	 */
	private List<String> parseSymbols(File commonSymbolsFile) throws IOException, CancelledException {
		// Check if the common symbols file exists
		if (commonSymbolsFile.exists() == false) {
			return null;
		}

		// If it exists, read the file
		BufferedReader reader = new BufferedReader(new FileReader(commonSymbolsFile));

		// Create a new linked list to store the common symbols in
		List<String> commonSymbols = new LinkedList<>();

		// Read a single line from the file
		String line = reader.readLine();

		// Iterate over all lines
		while (line != null) {
			/*
			 * If the monitor isn't cancelled, continue, else throw an exception which
			 * causes the whole script to halt
			 */
			monitor.checkCancelled();

			// If the line of the length is not zero
			if (line.length() != 0) {
				// Add it to the list
				commonSymbols.add(line);
			}
			// Read the next line
			line = reader.readLine();
		}

		// Once the entire file has been read, close the file access
		reader.close();

		// Return all common symbols
		return commonSymbols;
	}

	/**
	 * Recursively generate a mapping for all programs within the given folder and
	 * its sub-folders
	 * 
	 * @param folder              the folder to start in
	 * @param languageIdMapping   the LanguageID mapping which is populated within
	 *                            each call
	 * @param rawLanguageIds      the raw LanguageIDs
	 * @param languageIds         the LanguageID
	 * @param compilerSpecMapping the compiler spec mapping
	 * @throws CancelledException
	 */
	private void generateLanguageIdProgramMapping(Map<String, List<DomainFile>> languageIdMapping, DomainFolder folder,
			Set<String> rawLanguageIds, Set<String> languageIds, Map<String, List<DomainFile>> compilerSpecMapping)
			throws CancelledException {
		// Iterate over all domain files within the given folder
		for (DomainFile domainFile : folder.getFiles()) {
			/*
			 * As within any longer loop, a cancel check is present to allow a user to
			 * cancel the script in a timely manner
			 */
			monitor.checkCancelled();

			/*
			 * Only if the file is of the "PROGRAM" type, it is to be used
			 */
			if (domainFile.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
				Map<String, String> metadata = domainFile.getMetadata();

				String languageId = metadata.get("Language ID");
				if (languageId != null) {
					rawLanguageIds.add(languageId);

					/*
					 * An example of a raw language ID is "x86:LE:32:default (3.0)". Splitting by
					 * the space removes the version number, giving the language ID that is required
					 * for later use.
					 */
					String filteredLanguageId = languageId.split(" ")[0];

					languageIds.add(filteredLanguageId);

					/*
					 * Attempt to get the value from the mapping for the given key. If the result is
					 * null, no such key (nor value) is present in the mapping.
					 */
					List<DomainFile> domainFiles = languageIdMapping.get(filteredLanguageId);

					/*
					 * If the result is null, there is no key in the mapping, meaning it is new. A
					 * new list is created, and the key and value are added to the mapping.
					 */
					if (domainFiles == null) {
						domainFiles = new ArrayList<>();
						domainFiles.add(domainFile);
						languageIdMapping.put(filteredLanguageId, domainFiles);
					} else {
						/*
						 * Since the list from the mapping is not null, the key exists with a value. Add
						 * the current file to the list, and overwrite the mapping's entry with the new
						 * value for the given key.
						 */
						domainFiles.add(domainFile);
						languageIdMapping.put(filteredLanguageId, domainFiles);
					}

				}
			}
		}
		// Iterate over all folders within the given folder
		for (DomainFolder domainFolder : folder.getFolders()) {
			monitor.checkCancelled();
			generateLanguageIdProgramMapping(languageIdMapping, domainFolder, rawLanguageIds, languageIds,
					compilerSpecMapping);
		}
	}

	/**
	 * Populates an FIDB file based on the given list of programs for the given
	 * language ID, excluding the given common symbols
	 * 
	 * @param fidDb          the database to populate
	 * @param languageID     the LanguageID to match with
	 * @param programs       the programs to parse
	 * @param commonSymbols  the common symbols to exclude
	 * @param reporter       the report to use when returning results
	 * @param projectName    the project name to use within the database
	 * @param projectVersion the version to use within the database
	 * @throws CancelledException
	 */
	private void createLibraryFromPrograms(FidDB fidDb, LanguageID languageID, List<DomainFile> programs,
			List<String> commonSymbols, FidReporter reporter, String projectName, String projectVersion)
			throws CancelledException {
		/*
		 * Set the library name, version, and variant
		 */
		String libraryName = projectName;
		String libraryVersion = projectVersion;
		String libraryVariant = languageID.getIdAsString();

		// Create the message
		String message = "[" + libraryVariant + "] Generating \"" + libraryName + " (" + libraryVersion
				+ ")\" based on " + programs.size() + " files";
		// Log the message
		log(message, false);
		// Set the monitor message to inform the analyst when running via a GUI
		monitor.setMessage(message);

		try {
			// Call the FID service to create populate the new library
			FidPopulateResult result = fidService.createNewLibraryFromPrograms(fidDb, libraryName, libraryVersion,
					libraryVariant, programs, null, languageID, null, commonSymbols, TaskMonitor.DUMMY);
			// report the results via the reporter
			reporter.report(result);
		} catch (MemoryAccessException e) {
			Msg.showError(this, null, "Unexpected memory access exception", "Please notify the Ghidra team:", e);
		} catch (VersionException e) {
			Msg.showError(this, null, "Version Exception",
					"One of the programs in your domain folder cannot be upgraded: " + e.getMessage());
		} catch (IllegalStateException e) {
			Msg.showError(this, null, "Illegal State Exception", "Unknown error: " + e.getMessage());
		} catch (IOException e) {
			Msg.showError(this, null, "FidDb IOException", "Please notify the Ghidra team:", e);
		}
	}

	/**
	 * Creates a new FunctionID database file
	 * 
	 * @param fidbFile    the file to be created
	 * @param fidFileName the file name to use
	 * @return the newly created FIDB file with write permissions
	 * @throws IOException
	 * @throws VersionException
	 */
	private FidDB createFidDB(File fidbFile, String fidFileName) throws IOException, VersionException {
		// Declare the object
		FidFile fidFile = null;

		// Get the FID file manager
		FidFileManager fidFileManager = FidFileManager.getInstance();

		// Create a new database
		fidFileManager.createNewFidDatabase(fidbFile);

		// Get all user added FIDB files
		List<FidFile> fids = fidFileManager.getUserAddedFiles();

		// Iterate over all FIDB files
		for (FidFile fid : fids) {
			// If the name equals the given file name
			if (fid.getName().equalsIgnoreCase(fidFileName)) {
				// If the match is there, set the return variable and break the loop
				fidFile = fid;
				break;
			}
		}

		// If no matching file was found, something went wrong and null is returned
		if (fidFile == null) {
			return null;
		}

		// Return the FIDB file with write permissions
		return fidFile.getFidDB(true);
	}

	@Override
	protected void run() throws Exception {
		/*
		 * A note about the askSomething functions. This script is intended to be
		 * executed by Ghidra in its headless mode, since the GUI serves no purpose in
		 * this script. Any askSomething function will take an argument from the
		 * command-line interface when running headless. As such, it allows one to use
		 * the command-line interface in an easy manner, or with the help of a
		 * properties file. In this case, all askSomething functions are listed in the
		 * start of the run-method, since the command-line interface argument order
		 * matters. This is a convenient way for users to understand what arguments are
		 * to be provided when running this script headless, without going over all code
		 * within this script.
		 */

		/*
		 * Ask for the project name, which is to be used in the to-be created FIDBs
		 */
		String projectName = askString("Project name", "What is the project name?");

		/*
		 * Ask for the project version, which is to be used in the to-be created FIDBs
		 */
		String projectVersion = askString("Project version", "What is the project version?");

		/*
		 * Ask for the output folder. This will be the location where the FIDB files
		 * along with the log file will be written to.
		 */
		String outputFolder = askString("Desired output folder", "What is the desired output folder?");

		// Create a file object for the output folder
		File outputFolderFile = new File(outputFolder);

		// If the output folder does not exist, create all required folders
		if (outputFolderFile.exists() == false) {
			outputFolderFile.mkdirs();
		}

		/*
		 * Get the absolute path for the output folder, excluding a trailing folder
		 * separator
		 */
		outputFolder = outputFolderFile.getAbsolutePath();

		/*
		 * Ask if a common symbols file is to be used
		 */
		boolean useCommonSymbolsFile = askYesNo("Common symbols file usage",
				"Do you want to use a common symbols file?");

		/*
		 * The path to the symbols file, if desired
		 */
		String symbolsFilePath = null;

		/*
		 * The file object which refers to the provided path
		 */
		File commonSymbolsFile = null;

		/*
		 * The list of symbols
		 */
		List<String> symbols = null;

		/*
		 * If a common symbols file is desired, the path to said file is requested,
		 * after which a file object pointing to said location is instantiated. Lastly,
		 * the symbols are parsed, and stored in the symbols list. If the common symbols
		 * file cannot be found, the script returns early with a related error message
		 */
		if (useCommonSymbolsFile) {
			symbolsFilePath = askString("Common symbols file location",
					"What is the location of the common symbols file?");
			log("Received the following location for the common symbols file: " + symbolsFilePath, false);
			commonSymbolsFile = new File(symbolsFilePath);
			if (commonSymbolsFile.exists() == false) {
				log("Cannot find the common symbols file:" + symbolsFilePath, true);
				return;
			}
			symbols = parseSymbols(commonSymbolsFile);
		}

		/*
		 * Initialise the FunctionID service
		 */
		fidService = new FidService();

		/*
		 * Initialises the log file object
		 */
		File log = new File(outputFolder + File.separator + "log.txt");

		/*
		 * Check if the log file exists. If it does, no action is required, as data can
		 * be appended to it. If it does not, the file itself is created
		 */
		if (log.exists() == false) {
			log.createNewFile();
		}

		/*
		 * Set the log file, which is used by the log function
		 */
		logFile = log.toPath();

		/*
		 * Logging is possible from this point
		 */
		log("Received project name: " + projectName, false);
		log("Received project version: " + projectVersion, false);
		log("Received output folder path: " + outputFolder, false);
		log("Received choice with regards to the usage of a common symbols file: " + useCommonSymbolsFile, false);		

		/*
		 * Initialise a new report instance, to later report on the FIDB generation
		 * results
		 */
		FidReporter reporter = new FidReporter();

		/*
		 * Gets the root folder of the current project, allowing the recursive calls
		 * later on to start at the root node
		 */
		DomainFolder rootFolder = state.getProject().getProjectData().getRootFolder();

		/*
		 * Contains a mapping of the original compiler spec IDs for the given list of
		 * files
		 */
		Map<String, List<DomainFile>> compilerSpecMapping = new HashMap<>();

		/*
		 * Contains all language IDs without version information
		 */
		Set<String> languageIds = new HashSet<>();

		/*
		 * Contains all language IDs with version information
		 */
		Set<String> rawLanguageIds = new HashSet<>();

		/*
		 * Initialises the mapping of language IDs and their respective domain files
		 */
		Map<String, List<DomainFile>> languageIdProgramMapping = new HashMap<>();

		/*
		 * Generate a mapping, stored in a global variable, which contains unique
		 * language ID strings as a key, and a list of programs associated with said
		 * language ID as value. This mapping is used later on to make FIDBs for each
		 * language ID, with the respective files.
		 */
		generateLanguageIdProgramMapping(languageIdProgramMapping, rootFolder, rawLanguageIds, languageIds,
				compilerSpecMapping);

		/*
		 * Create a log message with all unique language IDs, including their version
		 */
		String collectLanguageIds = "Collected language IDs and their versions:\n";
		for (String id : rawLanguageIds) {
			collectLanguageIds += "\t" + id + "\n";
		}

		/*
		 * Write the message to Ghidra's console and the log file
		 */
		log(collectLanguageIds, false);

		/*
		 * Create a string which is to be logged, which contains each unique language ID
		 * and the number of files that are to be processed for said language ID
		 */
		String languageIdFileMessage = "";
		for (Map.Entry<String, List<DomainFile>> entry : languageIdProgramMapping.entrySet()) {
			String languageID = entry.getKey();
			List<DomainFile> domainFiles = entry.getValue();

			languageIdFileMessage += languageID + " contains " + domainFiles.size() + " files\n";
		}

		// Log the language ID and file summary
		log(languageIdFileMessage, false);

		/*
		 * Iterate over the language IDs without version information
		 */
		for (String id : languageIds) {
			/*
			 * Replace the colon with a dot to avoid invalid file name errors. The replace
			 * all function uses regular expressions for both arguments, meaning that the
			 * dot has to be escaped
			 */
			String fileName = id.replaceAll(":", "\\.") + ".fidb";

			/*
			 * The FIDB file name is the file name that the file will have on disk, based on
			 * the project name, project version, and the language ID
			 */
			String fidFileName = projectName.replaceAll(" ", "\\.") + "_" + projectVersion.replaceAll(" ", "\\.") + "_"
					+ fileName;

			// Create a file object for the FIDB file
			File fidbFile = new File(outputFolder + File.separator + fidFileName);

			/*
			 * The createNewFidDatabase function requires the file to NOT exist, meaning it
			 * needs to be deleted if it exists
			 */
			if (fidbFile.exists()) {
				String error = "The FIDB file already exists: " + fidbFile.getAbsolutePath();
				log(error, true);
				return;
			}

			/*
			 * Create the FIDB file
			 */
			FidDB fidDb = createFidDB(fidbFile, fidFileName);

			/*
			 * If createFidDB returns null, the file could not be found, and the execution
			 * needs to exit
			 */
			if (fidDb == null) {
				log("Cannot find any FIDB file named \"" + fidFileName + "\"", true);
				return;
			}

			/*
			 * Create a language ID object, which is used and required during the generation
			 * of the FIDB
			 */
			LanguageID languageID = new LanguageID(id);

			/*
			 * A list of all programs which fall under the given language ID, within the
			 * given Ghidra project
			 */
			List<DomainFile> programs = languageIdProgramMapping.get(id);

			/*
			 * Generate the hashes for functions for each program in the list, for the given
			 * language ID
			 */
			createLibraryFromPrograms(fidDb, languageID, programs, symbols, reporter, projectName, projectVersion);

			// Save the database, otherwise all changes will be lost
			fidDb.saveDatabase("Saving", monitor);

			// Close the FIDB
			fidDb.close();
		}
	}
}