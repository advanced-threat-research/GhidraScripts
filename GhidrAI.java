//Gets all functions within the program and allows one to see the complexity depth of each function. The graph related code has been taken from and inspired by Ghidra's base: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/cmd/module/ComplexityDepthModularizationCmd.java#L43
//@author Max 'Libra' Kersten for Trellix
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.GraphFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;

public class GhidrAI extends GhidraScript {

	/*
	 * The number of seconds the decompiler will run before timing out
	 */
	private final int DECOMPILER_TIMEOUT = 600;

	/*
	 * The number of threads via which the AI LLM provider is contacted. This
	 * decreases the wait time on the LLM as multiple functions are handled at the
	 * same time. If your LLM cannot handle multiple connections, adjust this value.
	 */
	private final int THREAD_COUNT = 10;

	/*
	 * The number of milliseconds to wait before the HTTP request times out
	 */
	private final int POST_REQUEST_TIMEOUT = 120_000;

	/*
	 * The HTTP URL to the LLM API
	 */
	private String API_URL;

	/*
	 * True if functions should be renamed, false if not. Only functions starting
	 * with FUN_ are renamed if this is true.
	 */
	private boolean RENAME_FUNCTION;

	/*
	 * True if variables within functions should be renamed
	 */
	private boolean RENAME_VARIABLES;

	/*
	 * The Google JSON handling library which is included in Ghidra, used to convert
	 * the JSON response from the LLM proxy
	 */
	private Gson gson;

	/*
	 * Ghidra's automatic analysis manager, used to check if one or more analyzers
	 * are still running
	 */
	private AutoAnalysisManager autoAnalysisManager;

	@Override
	protected void run() throws Exception {
		/*
		 * Required input:
		 * 
		 * - AI API URL
		 * 
		 * - Rename function based on suggestion: yes/no
		 * 
		 * - Rename variables based on suggestions: yes/no
		 */

		// Get all provided values
		API_URL = askString("AI API URL", "The URL where the AI's API is accessible at");
		RENAME_FUNCTION = askYesNo("", "Rename the function based on the AI's suggestion");
		RENAME_VARIABLES = askYesNo("", "Rename variables based on the AI's suggestions");

		// Create a string to provide the feedback to the user
		String inputFeedback = "Received input:\n";
		inputFeedback += "\tAI URL:                     " + API_URL + "\n";
		inputFeedback += "\tRename functions:           " + RENAME_FUNCTION + "\n";
		inputFeedback += "\tRename variables:           " + RENAME_VARIABLES;

		// Log the input feedback
		println(inputFeedback);

		// Now that all checks are done, the variables in the class are initialised
		gson = new Gson();
		autoAnalysisManager = AutoAnalysisManager.getAnalysisManager(currentProgram);
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);

		/*
		 * Notify the user of the current activity. Generating the complexity graph
		 * takes a bit, but each step is relatively small. As such, it is summarised as
		 * a single-step task to the user
		 */
		monitor.initialize(1, "Generating the complexity graph for the current program");

		// Generate the complexity graph
		GDirectedGraph<CodeBlockVertex, CodeBlockEdge> callGraph = createCallGraph();
		Map<CodeBlockVertex, Integer> complexityDepth = GraphAlgorithms.getComplexityDepth(callGraph);
		List<List<Function>> partition = createFunctionList(complexityDepth);

		// Remove the empty levels from the list
		partition = cleanAndReverseList(partition);

		int currentFunctionCount = 0;
		int totalFunctionCount = 0;
		for (List<Function> list : partition) {
			totalFunctionCount += list.size();
		}

		// Increment the monitor, marking this task as complete
		monitor.increment();

		/*
		 * To iterate over the list from start to end (rather than end to start), you
		 * need to reverse the list. This can be done using
		 * Collections.reverse(partition).
		 */

		/*
		 * Declare the executor service variable. It is instantiated per level within
		 * the partition.
		 */
		ExecutorService executor;

		/*
		 * Iterate backwards over the list, handling the functions with the least
		 * complexity depth first
		 */
		for (int i = 0; i < partition.size(); i++) {
			// Get the functions for the complexity level
			List<Function> list = partition.get(i);

			if (list.isEmpty()) {
				continue;
			}

			/*
			 * Create the monitor message, taking the potential plurality of the function
			 * count into account
			 */
			String listSize = "Iterating over " + list.size() + " function";
			if (list.size() > 1) {
				listSize += "s";
			}
			String monitorMessage = listSize + " in level " + i + "/" + partition.size();

			/*
			 * Initialise the monitor with the message. Each thread will call back to the
			 * thread safe increment method
			 */
			monitor.initialize(list.size(), monitorMessage);

			/*
			 * The number of threads is equal to the globally set maximum number of thread
			 * counts unless the size of the list is less than that.
			 */
			if (list.size() > THREAD_COUNT) {
				executor = Executors.newFixedThreadPool(THREAD_COUNT);
			} else {
				executor = Executors.newFixedThreadPool(list.size());
			}

			// Iterate over each function within this complexity level
			for (Function function : list) {
				// Exclude thunk and external functions
				if (function.isThunk() || function.isExternal()) {
					continue;
				}

				/*
				 * Set the current value for the current function, so we can keep the analyst
				 * updated based on the number of functions (as only the current and total
				 * number of levels in the graph is shown via the monitor message
				 */
				currentFunctionCount++;
				/*
				 * Create a worker to schedule in the thread pool. The worker will connect with
				 * the LLM and use the response to modify the given function based on the
				 * predefined settings with regards to renaming.
				 */
				FunctionWorker worker = new FunctionWorker(decompiler, function, totalFunctionCount,
						currentFunctionCount);
				// Schedule the worker in the executor
				executor.execute(worker);
			}

			// Shut the executor down, meaning no new workers can be added
			executor.shutdown();

			// Wait until all workers have completed their work
			while (executor.isTerminated() == false) {
				// If the user cancels the script, cancel the execution
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				/*
				 * If the workers are running and the script isn't cancelled by the user, sleep
				 * for one second to avoid using CPU cycles and check again after the sleep
				 * finishes.
				 */
				Thread.sleep(1000);
			}
			/*
			 * Before moving on to the next level, we wait for any ongoing automatic
			 * analysis to complete
			 */
			waitUntilAutoAnalysisCompletes();
		}
	}

	/**
	 * A function to remove empty list entries from the list of lists. The functions
	 * within each list within the given list are also iterated over, excluding
	 * external and thunk functions, as these will not be handled afterwards
	 * 
	 * @param list the list which contains the levels, where each level is a list of
	 *             functions
	 * @return a list with the levels, where each level contains 1 or more
	 *         functions, and all included functions are non-thunk and non-external
	 */
	private List<List<Function>> cleanAndReverseList(List<List<Function>> list) {
		// The output variable
		List<List<Function>> output = new ArrayList<>();

		// Iterate backwards over the list
		for (int i = list.size(); i-- > 0;) {
			// Get the current level
			List<Function> level = list.get(i);
			// Skip empty levels
			if (level.isEmpty()) {
				continue;
			}
			// Create a new list of functions
			List<Function> functions = new ArrayList<>();
			// Iterate over the functions within the level
			for (Function f : level) {
				// Exclude external and thunk functions
				if (f.isExternal() || f.isThunk()) {
					continue;
				}
				// Add non-thunk and non-external functions to the list
				functions.add(f);
			}
			// Add the filtered level to the output variable
			output.add(functions);
		}

		/*
		 * Return the list with the levels, in the original order with the applied
		 * filters
		 */
		return output;
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
	 * This method only returns once the auto analysis manager is done analyzing. If
	 * the user cancels, a cancelled exception is thrown.
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

	/**
	 * A thread safe method to increment the monitor
	 */
	private synchronized void incrementMonitorThreadSafe() {
		// Does not check for cancellation
		monitor.incrementProgress();
	}

	/**
	 * A thread safe method to verify if a method's name is unique.
	 * 
	 * @param functionName The function name to verify
	 * @return true if the name is unique, false if not
	 */
	private synchronized boolean isUniqueFunctionName(String functionName) {
		for (Function function : currentProgram.getFunctionManager().getFunctionsNoStubs(currentProgram.getMinAddress(),
				true)) {
			if (function.getName().equalsIgnoreCase(functionName)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns a unique function name. If the name is not unique, an underscore is
	 * appended
	 * 
	 * @param functionName the name to check
	 * @return the unique name
	 */
	private synchronized String getUniqueFunctionName(String functionName) {
		if (isUniqueFunctionName(functionName)) {
			return functionName;
		}

		functionName += "_";
		return getUniqueFunctionName(functionName);
	}

	/**
	 * The class where the threaded execution to handle a given function is handled
	 */
	private class FunctionWorker implements Runnable {

		private DecompInterface decompiler;
		private Function function;
		int totalFunctionCount;
		int currentFunctionCount;

		public FunctionWorker(DecompInterface decompiler, Function function, int totalFunctionCount,
				int currentFunctionCount) {
			this.decompiler = decompiler;
			this.function = function;
			this.totalFunctionCount = totalFunctionCount;
			this.currentFunctionCount = currentFunctionCount;
		}

		/**
		 * The run method of the thread, not to be confused with the script's main run
		 * method!
		 */
		@Override
		public void run() {
			// Decompile the given function
			DecompileResults results = decompiler.decompileFunction(function, DECOMPILER_TIMEOUT, monitor);
			// Get the decompiled function
			DecompiledFunction dFunction = results.getDecompiledFunction();
			// Get the pseudo-C representation of the decompiled function
			String code = dFunction.getC();
			// Get the plate comment, if present
			String tempComment = getPlateComment(function.getEntryPoint());
			// If the comment is non-null, it exists
			if (tempComment != null) {
				/*
				 * Remove the comment from the pseudo-C representation to avoid overloading the
				 * LLM's context window
				 */
				code = code.replace(tempComment, "");
			}

			// Get the function's variables
			Variable[] variables = function.getAllVariables();

			// Contact the LLM and store the JSON-based response
			JsonResponse response = contactLLM(code);
			// If the response is null, an error occurred
			if (response == null) {
				// Print an error if there is an error
				printerr(
						"The LLM's return value cannot be parsed as the format is invalid or the LLM did not respond at all");
				// Return from the thread
				return;
			}

			// Declare and initialize the comment
			String comment = "";

			// Store the old function name
			String oldFunctionName = function.getName();
			// Get the new function name from the LLM response
			String newFunctionName = response.getFunctionName();
			// If the new name is present and is not an empty or whitespace-only string
			if (newFunctionName != null && newFunctionName.isBlank() == false) {
				// If functions should be renamed
				if (RENAME_FUNCTION) {
					// Only rename functions with default names
					if (function.getName().toLowerCase().startsWith("fun_")) {
						try {
							// Set the new name
							function.setName(getUniqueFunctionName(newFunctionName), SourceType.IMPORTED);
							// Log the rename to non-headless instances
							log(oldFunctionName + " -> " + newFunctionName, false);
							// Add the name change to the comment
							comment += "Changed " + oldFunctionName + " into " + newFunctionName + "\n\n";
						} catch (Exception ex) {
							printerr("Function renaming failed:\n" + ex.toString());
						}
					}
				}
				/*
				 * If the function should not be renamed, or if the function name does not start
				 * with fun_, the suggested name is still added to the comment
				 */
				if (RENAME_FUNCTION == false || function.getName().toLowerCase().startsWith("fun_") == false) {
					comment += "AI suggested function name: " + newFunctionName + "\n\n";
				}
			}

			// If one or more variables are present in the function and LLM response
			if (variables.length > 0 && response.getVariableNames() != null) {
				// Set the next part of the comment
				comment += "Variables:\n";
				// Iterate over all variables
				for (Variable variable : variables) {
					// Get the old name
					String oldVariableName = variable.getName();
					// Get the new name
					String newVariableName = response.getVariableNames().get(oldVariableName);
					// If the new name is non-null and is not an empty or whitespace-only string
					if (newVariableName != null && newVariableName.isBlank() == false) {
						// If variables should be renamed
						if (RENAME_VARIABLES) {
							try {
								// Set the name
								variable.setName(newVariableName, SourceType.IMPORTED);
							} catch (Exception ex) {
								printerr("Variable renaming failed:\n" + ex.toString());
							}
						}
						// Add the renaming to the comment
						comment += "\t\tAI variable name: \"" + oldVariableName + "\" -> \"" + newVariableName + "\"\n";
					}
				}
				// Log the variables in Ghidra, when running non-headless
				log("Variables for " + function.getName() + " renamed", false);
				comment += "\n";
			}

			// Get the summary from the LLM
			String summary = response.getSummary();
			// If the summary is non-null and is not an empty or whitespace-only string
			if (summary != null && summary.isBlank() == false) {
				// Add the summary to the comment
				comment += "AI function summary: " + summary;
			}

			// If the comment is not whitespace-only or empty
			if (comment.isBlank() == false) {
				// Set the comment to the function
				setComment(function, comment, false);
				// Log the summary addition for non-headless instances
				log("Summary for " + function.getName() + " added", false);
			}

			/*
			 * This message is always logged (when running headless and non-headless) to
			 * give an indication of the progress
			 */
			log("Completed " + function.getName() + " (" + currentFunctionCount + "/" + totalFunctionCount + ")", true);
			// Increment the monitor to update the progress in a thread safe manner
			incrementMonitorThreadSafe();
		}
	}

	/**
	 * Send the HTTP POST request to LLM
	 * 
	 * @param body the body of comma separated strings to check
	 * @return the JSON response from the server
	 * @throws IOException
	 */
	private String sendPostRequest(Map<String, String> headers, String body) throws IOException {
		URL url = URI.create(API_URL).toURL();
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.setRequestMethod("POST");

		for (Map.Entry<String, String> entry : headers.entrySet()) {
			connection.setRequestProperty(entry.getKey(), entry.getValue());
		}

		connection.setConnectTimeout(POST_REQUEST_TIMEOUT);
		connection.setReadTimeout(POST_REQUEST_TIMEOUT);

		connection.setDoOutput(true);
		try (OutputStream outputStream = connection.getOutputStream()) {
			byte[] rawBody = body.getBytes("utf-8");
			outputStream.write(rawBody, 0, rawBody.length);
		}

		// TODO use response code to potentially throw an exception
		int responseCode = connection.getResponseCode();

		try (BufferedReader bufferedReader = new BufferedReader(
				new InputStreamReader(connection.getInputStream(), "utf-8"))) {
			StringBuilder response = new StringBuilder();
			String line = null;
			while ((line = bufferedReader.readLine()) != null) {
				response.append(line.trim());
			}
			return response.toString();
		}
	}

	/**
	 * Prompt the LLM by providing the pseudo-C code as the argument
	 * 
	 * @param code the function's pseudo-C code
	 * @return the LLM's JSON response
	 * @throws IOException
	 */
	public String promptLlmApi(String code) throws IOException {
		Map<String, String> headers = new HashMap<>();
		headers.put("Content-Type", "application/json");
		headers.put("Accept", "application/json");

		String prompt = "For the following decompiled code from Ghidra, suggest a new name for the function, summarise the function, and suggest new names for each of the variables in the function. State the old name of the variable and the new name. The response should be a JSON object with \"functionName\" as the key for the suggested function name, the key \"summary\" should contain the function's summary, and a nested JSON object named \"variableNames\" with the old variable names as keys, where the value of each key is the newly suggested name. The response should only the the requested JSON object, nothing else.\n\n"
				+ code;

		return sendPostRequest(headers, prompt);
	}

	/**
	 * Contact the LLM with the pseudo-C code and prompt
	 * 
	 * @param code the function's pseudo-C code
	 * @return a Java object in which the LLM's JSON response is already parsed
	 */
	private JsonResponse contactLLM(String code) {
		try {
			String response = promptLlmApi(code);

			if (response == null) {
				// return null;
			}
			JsonResponse jsonResponse = gson.fromJson(response, JsonResponse.class);
			return jsonResponse;
		} catch (IOException ex) {
			printerr(ex.toString());
			return null;
		} catch (JsonSyntaxException ex) {
			printerr(ex.toString());
			return null;
		} catch (Exception ex) {
			printerr(ex.toString());
			return null;
		}
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
	 * The class used to store the HTTP LLM API response in
	 */
	private class JsonResponse {
		private String functionName;
		private String summary;
		private Map<String, String> variableNames;

		@SuppressWarnings("unused")
		public JsonResponse() {

		}

		/**
		 * Gets the AI generated function name
		 * 
		 * @return the AI generated function name
		 */
		public String getFunctionName() {
			return functionName;
		}

		/**
		 * Gets the AI generated summary
		 * 
		 * @return the AI generated summary
		 */
		public String getSummary() {
			return summary;
		}

		/**
		 * Gets the mapping of the variable names (as keys) and the AI generated
		 * variable names (as a value, one for each key)
		 * 
		 * @return gets the AI generated variable names for the current variable names
		 */
		public Map<String, String> getVariableNames() {
			return variableNames;
		}
	}

	// From here onwards, the code is from the Ghidra source code

	private int getMaxLevel(Map<CodeBlockVertex, Integer> levelMap) {
		int maxLevel = -1;
		for (Integer level : levelMap.values()) {
			if (level > maxLevel) {
				maxLevel = level;
			}
		}
		return maxLevel;
	}

	private Function getFunctionFromCodeBlockVertex(CodeBlockVertex vertex) {
		Address startAddress = vertex.getCodeBlock().getFirstStartAddress();
		Function function = getFunctionAt(startAddress);
		return function;
	}

	private List<List<Function>> createFunctionList(Map<CodeBlockVertex, Integer> levelMap) {
		List<List<Function>> levelList = new ArrayList<>();
		int maxLevel = getMaxLevel(levelMap);
		for (int i = 0; i <= maxLevel; i++) {
			levelList.add(new ArrayList<Function>());
		}
		for (CodeBlockVertex vertex : levelMap.keySet()) {
			int reverseLevel = maxLevel - levelMap.get(vertex);
			Function function = getFunctionFromCodeBlockVertex(vertex);
			if (function != null) {
				levelList.get(reverseLevel).add(function);
			}
		}
		return levelList;
	}

	protected GDirectedGraph<CodeBlockVertex, CodeBlockEdge> createCallGraph() throws CancelledException {

		Map<CodeBlock, CodeBlockVertex> instanceMap = new HashMap<>();
		GDirectedGraph<CodeBlockVertex, CodeBlockEdge> graph = GraphFactory.createDirectedGraph();
		CodeBlockIterator codeBlocks = new BasicBlockModel(currentProgram, true).getCodeBlocks(monitor);
		while (codeBlocks.hasNext()) {
			CodeBlock block = codeBlocks.next();

			CodeBlockVertex fromVertex = instanceMap.get(block);
			if (fromVertex == null) {
				fromVertex = new CodeBlockVertex(block);
				instanceMap.put(block, fromVertex);
				graph.addVertex(fromVertex);
			}

			// destinations section
			addEdgesForDestinations(graph, fromVertex, block, instanceMap);
		}
		return graph;
	}

	private void addEdgesForDestinations(GDirectedGraph<CodeBlockVertex, CodeBlockEdge> graph,
			CodeBlockVertex fromVertex, CodeBlock sourceBlock, Map<CodeBlock, CodeBlockVertex> instanceMap)
			throws CancelledException {

		CodeBlockReferenceIterator iterator = sourceBlock.getDestinations(monitor);
		while (iterator.hasNext()) {
			monitor.checkCancelled();

			CodeBlockReference destination = iterator.next();
			CodeBlock targetBlock = getDestinationBlock(destination);
			if (targetBlock == null) {
				continue; // no block found
			}

			CodeBlockVertex targetVertex = instanceMap.get(targetBlock);
			if (targetVertex == null) {
				targetVertex = new CodeBlockVertex(targetBlock);
				instanceMap.put(targetBlock, targetVertex);
			}

			graph.addVertex(targetVertex);
			graph.addEdge(new CodeBlockEdge(fromVertex, targetVertex));
		}
	}

	private CodeBlock getDestinationBlock(CodeBlockReference destination) throws CancelledException {

		Address targetAddress = destination.getDestinationAddress();
		CodeBlock targetBlock = new BasicBlockModel(currentProgram, true).getFirstCodeBlockContaining(targetAddress,
				monitor);
		if (targetBlock == null) {
			return null; // no code found for call; external?
		}

		return targetBlock;
	}
}
