//Query a BSim database and rename functions within the current program based on predefined thresholds. 
//If two or more matches are found above the threshold, the function is not renamed, but the names are added in a comment, 
//along with contextually relevant information.
//@author Max 'Libra' Kersten for Trellix, based on Ghidra's QueryFunction script
//@category Bsim
//@keybinding
//@menupath
//@toolbar

import java.net.MalformedURLException;
import java.net.URL;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class BsimFunctionRenamer extends GhidraScript {

	/**
	 * The lower bound for a similarity to be considered. The value should be
	 * between 0 and 1, where 1 is an exact match. Note that a low bound with a low
	 * number of maximum matches (see {@link #MAXIMUM_BSIM_MATCHES_PER_FUNCTION}) is
	 * not really effective, since the highest matches are returned first.<br>
	 * <br>
	 * The combination of these two variables is delicate, as too many results can
	 * exhaust the available memory or result in an extremely long runtime of the
	 * script. The lower this bound is, the less trustworthy it is.
	 */
	private static double SIMILARITY_BOUND = 0.8;

	/**
	 * The maximum number of BSim matches per function. More matches consume more
	 * memory and take longer
	 */
	private static int MAXIMUM_BSIM_MATCHES_PER_FUNCTION = 20;

	/**
	 * The confidence bound is the lower bound for matches. As such, any match needs
	 * to have at least this confidence within the result.
	 */
	private static double CONFIDENCE_BOUND = 0.0;

	/**
	 * When set to <code>true</code>, functions with a single match (meaning a
	 * single match is found, or multiple matches with the exact same name in the
	 * database) are renamed to the detected function name
	 */
	private boolean RENAME_SINGLE_MATCH = false;

	/**
	 * When set to <code>true</code> and multiple matches are found for a given
	 * function, the shortest function name will be selected. If all other names
	 * contain the shortest name, it is renamed to the shortest name. If not, the
	 * function is not renamed.
	 */
	private boolean RENAME_MULTI_MATCH = false;

	/**
	 * When set to <code>true</code>, the {@link #CUSTOM_PREFIX} needs to be set,
	 * which is then used to rename generically matching functions.
	 */
	private boolean RENAME_GENERIC_MATCH = false;

	/**
	 * If {@link #RENAME_GENERIC_MATCH} is set to <code>true</code>, this value is
	 * used to prefix function names with, in order for them to be easily
	 * recognisable by analysts.
	 */
	private String CUSTOM_PREFIX = "";

	/**
	 * Creates a FunctionDatabase object based on the given URL. When using a local
	 * database, no file extension should be included within the full path to the
	 * database file!
	 * 
	 * @param databaseUrl the URL of the database to connect with
	 * @return a FunctionDatabase object to interact with the BSim database
	 * @throws IllegalArgumentException
	 * @throws MalformedURLException
	 */
	private FunctionDatabase openDatabase(String databaseUrl) throws IllegalArgumentException, MalformedURLException {
		// Create a URL object from the given string
		URL url = BSimClientFactory.deriveBSimURL(databaseUrl);
		// Create a non-async database object based on the given URL
		FunctionDatabase database = BSimClientFactory.buildClient(url, false);
		// Return the newly created database
		return database;
	}

	/**
	 * Queries the database for a single function from the current program and
	 * stores the results in the <code>matchHolders</code> list.
	 * 
	 * @param matchHolders the output list
	 * @param database     the BSim database
	 * @param gensig       the signature generation object
	 * @param function     the function from the current program to query
	 */
	private void queryDatabase(List<MatchHolder> matchHolders, FunctionDatabase database, GenSignatures gensig,
			Function function) {
		// Convert the function's casing to lower
		String lower = function.getName().toLowerCase();
		/*
		 * If the function does not start with "fun_", equals the default entrypoint
		 * ("entry") or is a thunk function, it is to be skipped. These functions can be
		 * skipped since they're irrelevant for the matching algorithm and would only
		 * consume resources and computation without yielding any results. As such, it
		 * is more efficient to skip them.
		 */
		if (lower.startsWith("fun_") == false || lower.equals("entry") || lower.startsWith("thunk_FUN_")) {
			return;
		}

		try {
			// Set the vector factory to match the database's vector factory type
			gensig.setVectorFactory(database.getLSHVectorFactory());
			// Open the current program
			gensig.openProgram(currentProgram, null, null, null, null, null);

			// Scan the current function
			gensig.scanFunction(function);

			// Declare and initialise the query
			QueryNearest query = new QueryNearest();
			query.manage = gensig.getDescriptionManager();
			query.max = MAXIMUM_BSIM_MATCHES_PER_FUNCTION;
			query.thresh = SIMILARITY_BOUND;
			query.signifthresh = CONFIDENCE_BOUND;

			// Get the response from the database
			ResponseNearest response = query.execute(database);

			// If the response is null, print the error and return
			if (response == null) {
				println(database.getLastError().message);
				return;
			}

			// Get all results from the response
			Iterator<SimilarityResult> similarityResultIterator = response.result.iterator();

			// Iterate over all entries
			while (similarityResultIterator.hasNext()) {
				// Get the result
				SimilarityResult similarityResult = similarityResultIterator.next();
				// Get the iterator from the result
				Iterator<SimilarityNote> similarityNoteIterator = similarityResult.iterator();

				/*
				 * Declare and initialise variables used to create custom objects based on match
				 * results
				 */
				List<FunctionMatch> matches = new ArrayList<>();
				Set<String> uniqueFunctionNames = new HashSet<>();
				Map<String, String> functionNameMapping = new HashMap<>();
				Map<String, List<FunctionMatch>> matchMapping = new HashMap<>();

				// Iterate over the similarity notes
				while (similarityNoteIterator.hasNext()) {
					// Get the note
					SimilarityNote similarityNote = similarityNoteIterator.next();
					// Get the function description
					FunctionDescription functionDescription = similarityNote.getFunctionDescription();
					// Get the executable record
					ExecutableRecord executableRecord = functionDescription.getExecutableRecord();

					// Declare the required fields for local processing
					String executable = executableRecord.getNameExec();
					String functionName = functionDescription.getFunctionName();
					String architecture = executableRecord.getArchitecture();
					double similarity = similarityNote.getSimilarity();
					double significance = similarityNote.getSignificance();

					// Get the function name in lower case
					String lowerCaseFunctionName = functionName.toLowerCase();
					// Store this name within a set
					uniqueFunctionNames.add(lowerCaseFunctionName);

					// If the function name mapping does not contain the key
					if (functionNameMapping.containsKey(lowerCaseFunctionName) == false) {
						// Add the names to the mapping
						functionNameMapping.put(lowerCaseFunctionName, functionName);
					}

					// Create a function match object
					FunctionMatch match = new FunctionMatch(function.getName(), executable, functionName, architecture,
							similarity, significance);

					// Add the match to the list of matches
					matches.add(match);
				}

				/*
				 * Iterate over all unique function names from the match for a given local
				 * function
				 */
				for (String lowerCaseFunctionName : uniqueFunctionNames) {
					// Create a new list to store all function matches in
					List<FunctionMatch> localMatches = new ArrayList<>();

					// Iterate over all matches
					for (FunctionMatch match : matches) {
						// If the currently iterated function name matches the match's function name
						if (match.getFunctionName().equalsIgnoreCase(lowerCaseFunctionName)) {
							// Add it to the list
							localMatches.add(match);
						}
					}
					// Sort the list
					localMatches.sort(Comparator.comparing(FunctionMatch::getExecutable).reversed());
					// Put the name and corresponding matches in the map
					matchMapping.put(functionNameMapping.get(lowerCaseFunctionName), localMatches);
				}

				// If there are matches
				if (matches.isEmpty() == false) {
					// Sort the matches
					matches.sort(Comparator.comparing(FunctionMatch::getExecutable).reversed());
					// Create a holding object
					MatchHolder holder = new MatchHolder(function, matchMapping);
					// Add the match holder to the list
					matchHolders.add(holder);
				}
			}
		} catch (Exception ex) {
			// TODO handle exceptions
		}
	}

	@Override
	public void run() throws Exception {
		// TODO replace with askString
		String databaseUrl = "file:/C:\\Users\\malwa\\bsim_databases\\bsim.golang-runtimes.windows.386-amd64.h2.medium-nosize";

		// TODO replace with askDouble
		SIMILARITY_BOUND = 0.7;

		// TODO replace with askInt
		MAXIMUM_BSIM_MATCHES_PER_FUNCTION = 20;

		// TODO replace with askYesNo
		RENAME_SINGLE_MATCH = true;

		// TODO replace with askYesNo
		RENAME_MULTI_MATCH = true;

		// TODO replace with askYesNo
		RENAME_GENERIC_MATCH = true;

		if (RENAME_GENERIC_MATCH) {
			// TODO replace with askString
			CUSTOM_PREFIX = "golang_";
		}

		/*
		 * A decimal format declared and instantiated here for later use allows a single
		 * instance to be reused
		 */
		DecimalFormat decimalFormat = new DecimalFormat("#.###");

		// Try to open the database
		try (FunctionDatabase database = openDatabase(databaseUrl)) {
			// If the database is not initialised, throw an error message and return early
			if (database.initialize() == false) {
				println(database.getLastError().message);
				return;
			}

			/*
			 * Declare and initiate the object to generate signatures, without the option to
			 * generate call graph information as it is not required for the purpose of this
			 * script and would only cause overhead
			 */
			GenSignatures gensig = new GenSignatures(false);

			// Declare and initialise a list of all match holders
			List<MatchHolder> matchHolders = new ArrayList<>();

			/*
			 * Declare and initialise variables used to print statistics at the end of the
			 * script's run to further inform the analyst of the results
			 */
			int functionCount = 0;
			int singleMatchRenameCount = 0;
			int multiMatchRenameCount = 0;
			int genericMatchRenameCount = 0;

			/*
			 * Iterate over all functions to get the total number of functions. Since the
			 * returned iterator by the function manager can only be iterated over once,
			 * this loop is only used to get the total number of functions
			 */
			for (@SuppressWarnings("unused")
			Function function : currentProgram.getFunctionManager().getFunctionsNoStubs(currentProgram.getMinAddress(),
					true)) {
				functionCount++;
			}

			/*
			 * Initialise the monitor on-screen with a message as to the current action, and
			 * set the maximum value to the number of functions, as each function will be
			 * queried to the given BSim database
			 */
			monitor.initialize(functionCount, "Querying the BSim database for all relevant local functions");

			// Get an iterator for all functions within the current program
			FunctionIterator functions = currentProgram.getFunctionManager()
					.getFunctionsNoStubs(currentProgram.getMinAddress(), true);

			// Iterate over each function within the current program
			for (Function function : functions) {
				/*
				 * Query the BSim database and populate the matchholders variable by appending
				 * new matches in the process
				 */
				queryDatabase(matchHolders, database, gensig, function);
				/*
				 * Checks if the script is cancelled and returns early, and increments the
				 * on-screen progress bar to inform the analyst
				 */
				monitor.increment();
			}

			/*
			 * At this stage, no further signatures have to be made, so the variable can be
			 * disposed of
			 */
			gensig.dispose();

			/*
			 * Initialise the monitor to depend on the found matches in the database, and
			 * the in-memory stored results thereof
			 */
			monitor.initialize(matchHolders.size(), "Renaming local functions based on matches");

			// Iterate over all matches
			for (MatchHolder matchHolder : matchHolders) {
				// Get the size of the current match's mapping
				int mappingSize = matchHolder.getMatchMapping().entrySet().size();

				// Iterate over the current match's mapping
				for (Map.Entry<String, List<FunctionMatch>> entry : matchHolder.getMatchMapping().entrySet()) {
					// Get the function name from the current entry
					String functionName = entry.getKey();
					// Get the matches with said function name
					List<FunctionMatch> matches = entry.getValue();

					// Declare and initialise the comment's base
					String comment = "Detected name: \"" + functionName + "\"\n";
					comment += "\nOriginal file, similarity, significance, architecture\n";

					// Iterate over each match within the match holder
					for (FunctionMatch match : matches) {
						/*
						 * Add the original file, similarity, significance, and architecture for each
						 * match
						 */
						comment += "\t" + match.getExecutable() + "\t\t" + decimalFormat.format(match.getSimilarity())
								+ "\t\t" + decimalFormat.format(match.getSignificance()) + "\t\t"
								+ match.getArchitecture() + "\n";
					}
					// Set the comment at the function within the current binary
					setComment(matchHolder.getLocalFunction(), comment, false);

					// Get the old function name
					String oldName = matchHolder.getLocalFunction().getName();

					/*
					 * If any of the rename options is selected, set the old function name in a
					 * comment at the top
					 */
					if (RENAME_SINGLE_MATCH || RENAME_MULTI_MATCH || RENAME_GENERIC_MATCH) {
						comment = "Old name: " + oldName;
						setComment(matchHolder.getLocalFunction(), comment, true);
					}
					/*
					 * If there is only a single match, and single matches are to be renamed
					 */
					if (mappingSize == 1 && RENAME_SINGLE_MATCH) {
						// If the old and new name are not the same (disregarding the casing)
						if (oldName.equalsIgnoreCase(functionName) == false) {
							// Rename the function
							renameFunction(matchHolder.getLocalFunction(), oldName, functionName);
							// Increment the single match rename counter
							singleMatchRenameCount++;
						}
					} else if (mappingSize >= 2) {
						/*
						 * If there are multiple matches, and a common name is to be picked if possible
						 * based on overlap in names
						 */
						if (RENAME_MULTI_MATCH) {
							// The shortest string is taken from the set
							String shortestFunctionName = getShortestString(matchHolder.getMatchMapping().keySet());
							// If all entries within the set contain said string
							if (allEntriesContain(matchHolder.getMatchMapping().keySet(), shortestFunctionName)) {
								// If the old name does not equal the shortest function name, disregarding the
								// casing
								if (oldName.equalsIgnoreCase(shortestFunctionName) == false) {
									// Rename the function
									renameFunction(matchHolder.getLocalFunction(), oldName, shortestFunctionName);
									// Increment the multi-match count
									multiMatchRenameCount++;
								}
							}
						}

						// If generic matches are enabled
						if (RENAME_GENERIC_MATCH) {
							/*
							 * If the the old name does not start with the custom prefix to set (meaning it
							 * is hasn't been renamed already)
							 */
							if (oldName.toLowerCase().startsWith(CUSTOM_PREFIX.toLowerCase()) == false) {
								// Declare the new name as the old name with the set prefix in front
								String newName = CUSTOM_PREFIX + oldName;
								// Rename the function
								renameFunction(matchHolder.getLocalFunction(), oldName, newName);
								// Increment the generic match count
								genericMatchRenameCount++;
							}
						}
					}
				}
				/*
				 * Increment the monitor to indicate one function has been handled. If the
				 * analyst cancelled the script at any point prior to the previous check it will
				 * now cancel and exit this script
				 */
				monitor.increment();
			}

			/*
			 * Print the statistics with regards to the renaming, so the analyst gets an
			 * easy overview of the effectiveness of this script's results
			 */
			println("Renamed " + singleMatchRenameCount + " single-match functions!");
			println("Renamed " + multiMatchRenameCount + " multi-match functions!");
			println("Renamed " + genericMatchRenameCount + " generic match functions!");

			println((singleMatchRenameCount + multiMatchRenameCount + genericMatchRenameCount) + "/" + functionCount
					+ " of the matching functions were renamed");
			println(matchHolders.size() + "/" + functionCount
					+ " of the functions were matched in the database, based on the given similarity threshold");
		}
	}

	/**
	 * A wrapper function to rename a function based on the given new name, mark it
	 * as a user defined new name, and print the function rename to the console.
	 * 
	 * @param function the function to rename
	 * @param oldName  the old name of the function
	 * @param newName  the new name of the function
	 * @throws DuplicateNameException
	 * @throws InvalidInputException
	 */
	private void renameFunction(Function function, String oldName, String newName)
			throws DuplicateNameException, InvalidInputException {
		// Set the function name
		function.setName(newName, SourceType.USER_DEFINED);
		/*
		 * Print the old and new function names, the later of which is clickable in the
		 * console. Note that this line of code is only reached if no exception is
		 * thrown when setting the new function name, avoiding a mismatch between the
		 * console and the renamed functions
		 */
		println("Renamed " + oldName + " to " + newName);
	}

	/**
	 * A helper function to check if all entries within the given set contain a
	 * given string, disregarding the casing. This helper function is simplistic in
	 * nature and can be altered to suit one's specific needs. In this case, the
	 * overlap in strings within the set is measured.
	 * 
	 * @param set  the set of strings to iterate over
	 * @param part the string each item within the set ought to contain,
	 *             disregarding the casing
	 * @return true if all entries match the given part (disregarding casing), false
	 *         if not
	 */
	private boolean allEntriesContain(Set<String> set, String part) {
		// Iterate over all entries in the set
		for (String s : set) {
			// Check if the entry in the set contains the part, disregarding casing
			if (s.toLowerCase().contains(part.toLowerCase()) == false) {
				// Return false if the entry does not contain the match
				return false;
			}
		}
		// Return true if all entries have been iterated without failing to find a match
		return true;
	}

	/**
	 * Helper function to get the shortest string from a set of strings
	 * 
	 * @param set the set where to obtain the shortest string from
	 * @return the shortest string found within the set
	 */
	private String getShortestString(Set<String> set) {
		// If the set object is null, or if it is empty, return null
		if (set == null || set.isEmpty()) {
			return null;
		}
		/*
		 * Declare and initialise the size variable, setting it to the maximum value it
		 * can hold, for which can be checked later
		 */
		int size = Integer.MAX_VALUE;

		// Declare and initialise an empty string
		String result = "";

		// Iterate over all entries in the set
		for (String s : set) {
			// Get the length of the current entry's length
			int length = s.length();
			/*
			 * If the length of this entry is smaller than the smallest noted size thus far,
			 * save the size and result
			 */
			if (length < size) {
				size = length;
				result = s;
			}
		}

		// Return the result once all entries have been iterated over
		return result;
	}

	/**
	 * Helper function to set a comment at a given function, with the indication if
	 * this comment should be at the top or bottom of any already existing function
	 * comment at this function
	 * 
	 * @param function  the function to set a comment at
	 * @param comment   the comment to set at the given function
	 * @param pushToTop true if the function's existing comment (if any) should be
	 *                  put below this comment, false if not
	 */
	private void setComment(Function function, String comment, boolean pushToTop) {
		// Get the old comment, which is null if no comment is present
		String oldComment = function.getComment();
		// Check for the existence of the old comment
		if (oldComment != null) {
			// If it is present, trim the comment to avoid redundant whitespace
			oldComment = oldComment.trim();
			// If the string, post trimming, is not empty nor blank (which also checks if it
			// is empty)
			if (oldComment.isEmpty() == false && oldComment.isBlank() == false) {
				// If the comment should be at the top, place it at the top
				if (pushToTop) {
					comment += "\n\n" + oldComment;
				} else { // Else put it at the bottom
					comment = oldComment += "\n\n" + comment;
				}
			}
		}

		/**
		 * Set the comment, which contains the prior comment at the correct placement
		 * with regards to the given boolean if it existed
		 */
		function.setComment(comment);
	}

	/**
	 * A class to hold a local function (from the current program) with BSim matches
	 * in a map
	 */
	class MatchHolder {

		/**
		 * The local function from the current program
		 */
		private Function localFunction;

		/**
		 * The mapping with function names and matches, compared to the local function
		 */
		private Map<String, List<FunctionMatch>> matchMapping;

		public MatchHolder(Function localFunction, Map<String, List<FunctionMatch>> matchMapping) {
			super();
			this.localFunction = localFunction;
			this.matchMapping = matchMapping;
		}

		/**
		 * Gets the local function to which the corresponding mapping belongs, based on
		 * the BSim query
		 * 
		 * @return the local function object
		 */
		public Function getLocalFunction() {
			return localFunction;
		}

		/**
		 * The mapping with matches, belonging to the function within this object
		 * 
		 * @return the mapping
		 */
		public Map<String, List<FunctionMatch>> getMatchMapping() {
			return matchMapping;
		}
	}

	class FunctionMatch {
		/**
		 * The name of the function from the current program
		 */
		private String localFunctionName;

		/**
		 * The executable from which the match originates
		 */
		private String executable;

		/**
		 * The function name of the match
		 */
		private String functionName;

		/**
		 * The LanguageID from the match
		 */
		String architecture;

		/**
		 * The similarity of the match compared to the local function
		 */
		private double similarity;

		/**
		 * The significance of the match
		 */
		private double significance;

		public FunctionMatch(String localFunctionName, String executable, String functionName, String architecture,
				double similarity, double significance) {
			super();
			this.localFunctionName = localFunctionName;
			this.executable = executable;
			this.functionName = functionName;
			this.architecture = architecture;
			this.similarity = similarity;
			this.significance = significance;
		}

		/**
		 * The name of the function in the current program
		 * 
		 * @return
		 */
		public String getLocalFunction() {
			return localFunctionName;
		}

		/**
		 * The executable from which the match originates
		 * 
		 * @return
		 */
		public String getExecutable() {
			return executable;
		}

		/**
		 * The function name from the match
		 * 
		 * @return
		 */
		public String getFunctionName() {
			return functionName;
		}

		/**
		 * The LanguageID from the match
		 * 
		 * @return
		 */
		public String getArchitecture() {
			return architecture;
		}

		/**
		 * The similarity of the function from the current program compared to the
		 * matching function
		 * 
		 * @return
		 */
		public double getSimilarity() {
			return similarity;
		}

		/**
		 * The significance of the match
		 * 
		 * @return
		 */
		public double getSignificance() {
			return significance;
		}
	}
}