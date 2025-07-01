//Colourises the complexity of a function where it is called in the disassembly listing. Light red is not complex, dark red is complex.
//@author Max 'Libra' Kersten for Trellix. The graph related code has been taken from and inspired by Ghidra's base: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/cmd/module/ComplexityDepthModularizationCmd.java#L43
//@category 
//@keybinding
//@menupath
//@toolbar

import java.awt.Color;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.viewer.listingpanel.PropertyBasedBackgroundColorModel;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.GraphFactory;
import ghidra.program.database.IntRangeMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;

public class ColouriseByComplexity extends GhidraScript {

	@Override
	protected void run() throws Exception {
		// Initialise the decompiler
		DecompInterface decompiler = new DecompInterface();
		// Open the current program
		decompiler.openProgram(currentProgram);

		// Get the call graph
		GDirectedGraph<CodeBlockVertex, CodeBlockEdge> callGraph = createCallGraph();
		// Obtain the complexity depth graph
		Map<CodeBlockVertex, Integer> complexityDepth = GraphAlgorithms.getComplexityDepth(callGraph);
		// Get the list of all levels within the graph
		List<List<Function>> partition = createFunctionList(complexityDepth);

		// Remove the empty levels from the list
		partition = cleanList(partition);

		// Iterate over the levels
		for (int i = 0; partition.size() > i; i++) {
			// Get the current list (or level, if you will)
			List<Function> list = partition.get(i);

			// Iterate over the functions within the current list
			for (Function function : list) {
				// Exclude thunk and external functions
				if (function.isThunk() || function.isExternal()) {
					continue;
				}

				/*
				 * Store the number of levels as a double, required to perform arithmetics that
				 * return a double
				 */
				double size = partition.size();

				// Get the current value, incremented by one since i is zero-based
				double currentValue = i + 1;

				/*
				 * Calculate the percentage of this level is relatively to the rest all levels
				 */
				double percentage = currentValue / size;

				/*
				 * One minus the percentage, since the first entry in the partition list, has
				 * the highest complexity depth
				 */
				double red = (1 - percentage) * 255;

				// Get all references to the function
				ReferenceIterator referenceIterator = currentProgram.getReferenceManager()
						.getReferencesTo(function.getEntryPoint());

				// Iterate over all references
				for (Reference ref : referenceIterator) {
					// Create the colour
					Color color = new Color((int) red, 0, 0);
					// Set the background colour in the listing for the reference
					setBackgroundColor(ref.getFromAddress(), ref.getFromAddress(), color);
				}
			}
		}
	}

	/**
	 * Takes a list of lists and returns a list of lists where none of the lists is
	 * empty
	 * 
	 * @param list the list to clean
	 * @return the same list but without any empty lists within
	 */
	private List<List<Function>> cleanList(List<List<Function>> list) {
		List<List<Function>> output = new ArrayList<>();

		for (List<Function> item : list) {
			if (item.isEmpty()) {
				continue;
			}
			output.add(item);
		}

		return output;
	}

	// Code below is taken from the Ghidra source code

	public void setBackgroundColor(Address min, Address max, Color c) {
		IntRangeMap map = getColorRangeMap(true);
		if (map != null) {
			map.setValue(min, max, c.getRGB());
		}
	}

	private IntRangeMap getColorRangeMap(boolean create) {
		IntRangeMap map = currentProgram.getIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
		if (map == null && create) {
			try {
				map = currentProgram.createIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
			} catch (DuplicateNameException e) {
				// can't happen since we just checked for it!
			}
		}
		return map;
	}

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