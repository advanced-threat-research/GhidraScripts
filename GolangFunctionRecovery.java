//Finds and creates functions with their original names, in Golang based PE and ELF files. Functions which have already been found by Ghidra will be renamed if a suitable name is found.  
//@author Max 'Libra' Kersten of Trellix' Advanced Research Center, based on the work by padorka@cujoai (https://github.com/getCUJO/ThreatIntel/blob/master/Scripts/Ghidra/go_func.py) 
//@category Golang
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class GolangFunctionRecovery extends GhidraScript {

	/**
	 * A boolean which defines if logging should be enabled. When prioritising
	 * speed, one might not be interested in getting all messages, but rather only
	 * the concluding message, along with potential error messages. As such, this
	 * boolean specifies if more logging should be enabled or disabled.</br>
	 * </br>
	 * The default value of this field is <code>true</code>.
	 */
	private static final boolean ENABLE_LOGGING = true;

	/**
	 * The mask to perform the logical AND with on the magic value
	 */
	private static final int MAGIC_MASK = 0xffffffff;

	/**
	 * The magic value for Golang 1.20 and above
	 * 
	 * @see <a href=
	 *      "https://github.com/golang/go/blob/master/src/debug/gosym/pclntab.go">Golang
	 *      pclntab source code</a>
	 */
	private static final int GO_120 = 0xfffffff1;

	/**
	 * The magic value for Golang 1.18
	 * 
	 * @see <a href=
	 *      "https://github.com/golang/go/blob/master/src/debug/gosym/pclntab.go">Golang
	 *      pclntab source code</a>
	 */
	private static final int GO_118 = 0xfffffff0;

	/**
	 * The magic value for Golang 1.16 through version 1.17
	 * 
	 * @see <a href=
	 *      "https://github.com/golang/go/blob/master/src/debug/gosym/pclntab.go">Golang
	 *      pclntab source code</a>
	 */
	private static final int GO_116 = 0xfffffffa;

	/**
	 * The magic value for Golang 1.2 through version 1.15
	 * 
	 * @see <a href=
	 *      "https://github.com/golang/go/blob/master/src/debug/gosym/pclntab.go">Golang
	 *      pclntab source code</a>
	 */
	private static final int GO_12 = 0xfffffffb;

	/**
	 * The default PC Quantum size (minimal instruction size), used in x86, x86_64,
	 * and WASM
	 * 
	 * @see <a href=
	 *      "https://github.com/golang/gofrontend/blob/master/libgo/goarch.sh">Golang
	 *      architecture documentation</a>
	 */
	private static final int INSTRUCTION_SIZE_ONE = 1;

	/**
	 * The PC Quantum size (minimal instruction size), used in RISCV, RISCV x64,
	 * S390, S390X, SH, and SHbe
	 * 
	 * @see <a href=
	 *      "https://github.com/golang/gofrontend/blob/master/libgo/goarch.sh">Golang
	 *      architecture documentation</a>
	 */
	private static final int INSTRUCTION_SIZE_TWO = 2;

	/**
	 * The PC Quantum size (minimal instruction size), used in ALPHA, ARM, ARMbe,
	 * M68K, MIPS, MIPSle, MIPS64p32, MIPS64p32le, MIPS64, MIPS64le, NIOS2, PPC,
	 * PPC64, PPC64le, SPARC, and SPARC64
	 * 
	 * @see <a href=
	 *      "https://github.com/golang/gofrontend/blob/master/libgo/goarch.sh">Golang
	 *      architecture documentation</a>
	 */
	private static final int INSTRUCTION_SIZE_FOUR = 4;

	/**
	 * The size of a pointer on X86
	 */
	private static final int POINTER_SIZE_X86 = 4;

	/**
	 * The size of a pointer on X64
	 */
	private static final int POINTER_SIZE_X64 = 8;

	/**
	 * The amount of functions which were recovered
	 */
	private static int functionCount = 0;

	@Override
	protected void run() throws Exception {
		// Get the executable format of the sample
		String executableFormat = currentProgram.getExecutableFormat();
		// Declare the pclntab variable
		Address pclntab;

		// Check if the executable format is a PE file
		if (executableFormat.equalsIgnoreCase("Portable Executable (PE)")) {
			// Optionally print a message to state the file type which has been detected
			log("PE file found");
			// The declaration and initialisation of potential pclntab magic values
			String[] pclntabMagicValues = { "\\xfb\\xff\\xff\\xff\\x00\\x00", "\\xfa\\xff\\xff\\xff\\x00\\x00",
					"\\xf0\\xff\\xff\\xff\\x00\\x00", "\\xf1\\xff\\xff\\xff\\x00\\x00" };
			// Get the gopclntab address by magic value
			pclntab = getGopclntabByMagicValue(pclntabMagicValues);
		} else if (executableFormat.equalsIgnoreCase("Executable and Linking Format (ELF)")) { // Check if the
																								// executable format is
																								// an ELF file
			// Optionally print a message to state the file type which has been detected
			log("ELF file found");
			// Get the gopclntab address by section name
			pclntab = getGopclntabBySectionName(".gopclntab");
		} else if (executableFormat.equalsIgnoreCase("Mac OS X Mach-O")) {
			// Optionally print a message to state the file type which has been detected
			log("Mach-O file found");
			// Get the gopclntab address by section name
			pclntab = getGopclntabBySectionName("__gopclntab");
		} else {
			/*
			 * Print an error message informing the user of the failure to find a suitable
			 * executable format
			 */
			printerr("Unspported file format: " + executableFormat);
			// Return, thus ending the script's execution
			return;
		}

		// If the pclntab could not be found, the script ends
		if (pclntab == null) {
			// Print an error message with the reason of the failure
			printerr("Cannot find the pclntab!");
			// End the script's execution
			return;
		}

		/*
		 * If execution continues, the pclntab was found. Optionally print a message to
		 * inform the user of the progress
		 */
		log(String.format("pclntab found at 0x%x!", pclntab.getOffset()));

		// Declare and initialise the pclntab magic value
		int magic = getInt(pclntab) & MAGIC_MASK;

		// Recover function names for functions in Golang version 1.20 and above
		if (magic == GO_120) {
			println("Golang 1.20 found, note that this script is experimental for this Golang version!");
			recoverFunctionNamesGo118Plus(pclntab);
		} else if (magic == GO_118) {
			// Recover function names for functions in Golang version 1.18 and above
			recoverFunctionNamesGo118Plus(pclntab);
		} else if (magic == GO_116) { // Determine if the magic value matches Golang version 1.16 and 1.17
			// Recover function names for functions in Golang versions 1.16 and 1.17
			renameFunc116(pclntab);
		} else if (magic == GO_12) {// Determine if the magic value matches Golang 1.15 through version 1.2
			/*
			 * Recover function names for functions in Golang version 1.15 through version
			 * 1.2
			 */
			recoverFunctionNamesGo12(pclntab);
		} else {
			// No matching magic value was found, of which the user is informed
			println("Unable to determine the .gopclntab magic value, so the assumption is made that it is Go 1.2 compatible");
			/*
			 * Recover function names for functions in Golang version 1.15 through version
			 * 1.2
			 */
			recoverFunctionNamesGo12(pclntab);
		}

		/*
		 * Inform the analyst of the total number of functions which has been renamed
		 * and/or created
		 */
		println("Total number of functions renamed and/or created: " + functionCount);
	}

	/**
	 * A wrapper function for the
	 * {@link ghidra.app.script.GhidraScript#println(String)} which is only called
	 * if the {@link #ENABLE_LOGGING} is <code>true</code>. The logging that is
	 * (potentially) passing through this function, is meant as optional logging.
	 * The final conclusion, as well as the logging of any error messages, should be
	 * printed via direct calls. The easy-to-omit nature of optional messages speeds
	 * up automated analysis by limiting the number of print calls.
	 * 
	 * @param message
	 */
	private void log(String message) {
		if (ENABLE_LOGGING) {
			println(message);
		}
	}

	/**
	 * Gets the gopclntab starting address based on a found magic value, if any
	 * 
	 * @param pclntabMagicValues possible magic values as byte strings written as
	 *                           strings (i.e. "\xab\xbc")
	 * @return the starting address of the gopclntab if it is found, null if it is
	 *         not found
	 * @throws MemoryAccessException
	 * @throws AddressOutOfBoundsException
	 */
	private Address getGopclntabByMagicValue(String[] pclntabMagicValues)
			throws MemoryAccessException, AddressOutOfBoundsException {
		// Iterate over all magic values
		for (String magic : pclntabMagicValues) {
			/*
			 * Look for the magic bytes within the current program, starting at the minimum
			 * address, with a maximum of 100 results
			 */
			Address[] pclntabs = findBytes(null, magic, 100);

			// Iterate over all results
			for (Address pclntab : pclntabs) {
				/*
				 * Bytes have been found based on the given magic value
				 */

				// Get the instruction's size quantum
				byte instructionSizeQuantum = getByte(pclntab.add(6));
				// Get the pointer size
				byte pointerSize = getByte(pclntab.add(7));

				/*
				 * Verify if both the instruction's quantum size and pointer size match the
				 * conditions, meaning the pclntab has been found
				 */
				if ((instructionSizeQuantum != INSTRUCTION_SIZE_ONE && instructionSizeQuantum != INSTRUCTION_SIZE_TWO
						&& instructionSizeQuantum != INSTRUCTION_SIZE_FOUR) == false
						|| (pointerSize != POINTER_SIZE_X86 && pointerSize != POINTER_SIZE_X64) == false) {
					return pclntab;
				}
			}
		}
		// If no results match the criteria, null is returned
		return null;
	}

	/**
	 * Gets the gopclntab by its section name (being ".gopclntab")
	 * 
	 * @return the starting address of the ".gopclntab" section
	 */
	private Address getGopclntabBySectionName(String sectionName) {
		// Iterate over all memory blocks within the program
		for (MemoryBlock memoryBlock : getMemoryBlocks()) {
			// Check if the block's name equals (ignoring the casing) the gopclntab section
			if (memoryBlock.getName().equalsIgnoreCase(sectionName)) {
				// Return the starting address of this section if it is found
				return memoryBlock.getStart();
			}
		}
		// Return null if the section is not found
		return null;
	}

	/**
	 * Creates a new function, or renames the function if it already exists, based
	 * on the newly found name, which is obtained via the name address variable
	 * 
	 * @param functionAddress the address of the function
	 * @param nameAddress     the address of the function's new name
	 * @throws DuplicateNameException
	 * @throws InvalidInputException
	 */
	private void createOrRenameFunction(Address functionAddress, Address nameAddress)
			throws DuplicateNameException, InvalidInputException {
		// Check if the variable is instantiated
		if (nameAddress == null) {
			// Return from the function if this is the case
			return;
		}

		// Get the data at the given address
		Data functionNameData = getDataAt(nameAddress);
		// If no data resides at this address
		if (functionNameData == null) {
			try {
				// Create an ASCII string within Ghidra
				functionNameData = createAsciiString(nameAddress);
			} catch (Exception e) {
				// Print an error if the ASCII string creation fails
				printerr(String.format("Unable to create an ASCII string at 0x%x!", nameAddress.getOffset()));
				// Return from the function if this fails
				return;
			}
		}

		/*
		 * Get the function name by getting the data's value, which in this case is a
		 * String but needs to be cast as the getValue function returns an Object
		 */
		String functionName = (String) functionNameData.getValue();

		// If the function name is null, blank, or empty
		if (functionName == null || functionName.isBlank()) {
			// Print an error
			printerr(String.format("No function name found at 0x%s!", Long.toHexString(nameAddress.getOffset())));
			// Return from the function
			return;
		}

		// Gets the function at the given address
		Function func = getFunctionAt(functionAddress);

		// If there is a function at the given address
		if (func != null) {
			// Get the old name
			String functionNameOld = func.getName();
			// Rename the function with the new name, without spaces
			func.setName(functionName.replace(" ", ""), SourceType.USER_DEFINED);
			// Optionally print the function name change, along with the location
			log("Function renamed from \"" + functionNameOld + "\" to \"" + functionName + "\", located at 0x"
					+ Long.toHexString(functionAddress.getOffset()));
		} else {
			// If no function exists at the given address, create one
			func = createFunction(functionAddress, functionName);
			// Optionally print the function name and address
			log("Function \"" + functionName + "\" created at 0x" + Long.toHexString(functionAddress.getOffset()));
		}

		// Increment the function count
		functionCount++;
	}

	/**
	 * Recovers function names for functions in Golang version 1.15 through version
	 * 1.2
	 * 
	 * @param pclntab the start address of the pclntab
	 * @throws MemoryAccessException
	 * @throws AddressOutOfBoundsException
	 * @throws DuplicateNameException
	 * @throws InvalidInputException
	 */
	private void recoverFunctionNamesGo12(Address pclntab)
			throws MemoryAccessException, AddressOutOfBoundsException, DuplicateNameException, InvalidInputException {
		// Get the pointer size
		byte pointerSize = getByte(pclntab.add(7));
		// Declare the number of functions tab variable
		long nFunctionTab;

		// If the pointer size fits a x64 system
		if (pointerSize == POINTER_SIZE_X64) {
			// Get a long value from the given address
			nFunctionTab = getLong(pclntab.add(8));
		} else { // Assume x86, meaning 4 bytes in size
			// Get an integer value from the given address
			nFunctionTab = getInt(pclntab.add(8));
		}

		// Get the function tab address
		Address functionTab = pclntab.add(8 + pointerSize);

		// Declare a copy of the function tab, named p
		Address p = functionTab;
		// Declare the function address variable
		Address functionAddress;
		// Declare the name offset variable
		long nameOffset;

		// Iterate over the number of functions
		for (int i = 0; i < nFunctionTab; i++) {
			// Check if the script's execution is cancelled
			if (monitor.isCancelled()) {
				// Break this loop, thus exiting the script's execution early
				break;
			}

			// If the pointer size fits a x64 system
			if (pointerSize == POINTER_SIZE_X64) {
				// Get the function address
				functionAddress = currentProgram.getAddressFactory().getAddress(Long.toHexString(getLong(p)).trim());
				// Increment p with the pointer size to move it to the next usable address
				p = p.add(pointerSize);
				// Get the name offset as a long, since the architecture is x64
				nameOffset = getLong(p);
			} else { // Assume x86, meaning 4 bytes in size
				// Get the function address
				functionAddress = currentProgram.getAddressFactory().getAddress(Long.toHexString(getInt(p)));
				// Increment p with the pointer size to move it to the next usable address
				p = p.add(pointerSize);
				// Get the name offset as an integer, since the architecture is x86
				nameOffset = getInt(p);
			}

			// Increment p with the pointer size to move it to the next usable address
			p = p.add(pointerSize);

			/*
			 * Gets the name pointer, which is located directly after the function name,
			 * hence the addition of the name offset and the pointer size to move to the
			 * next usable address
			 */
			Address namePointer = pclntab.add(nameOffset + pointerSize);
			// Get the address of the name, based on the pointer, which is always 32 bits in
			// size
			Address nameAddress = pclntab.add(getInt(namePointer));
			// Address nameAddress = pclntab.add(namePointer.getOffset());

			/*
			 * Create or rename the function at the address, with the name at the given
			 * address
			 */
			createOrRenameFunction(functionAddress, nameAddress);
		}
	}

	/**
	 * Recovers function names for functions in Golang version 1.16 and version 1.17
	 * 
	 * @param pclntab the start address of the pclntab
	 * @throws MemoryAccessException
	 * @throws AddressOutOfBoundsException
	 * @throws DuplicateNameException
	 * @throws InvalidInputException
	 */
	private void renameFunc116(Address pclntab)
			throws MemoryAccessException, AddressOutOfBoundsException, DuplicateNameException, InvalidInputException {
		// Get the size of the pointer
		byte pointerSize = getByte(pclntab.add(7));

		// Declare variables, whose value will depend on the architecture
		long nFunctionTab;
		long offset;
		Address functionNameTab;

		// If the pointer's size is equal to the size of a pointer on a x64 system
		if (pointerSize == POINTER_SIZE_X64) {
			// Get the corresponding long value
			nFunctionTab = getLong(pclntab.add(8));
			// Calculate the next offset
			offset = getLong(pclntab.add(8 + 2 * pointerSize));
			// Get the function name tab's address
			functionNameTab = pclntab.add(offset);
			// Calculate the next offset
			offset = getLong(pclntab.add(8 + 6 * pointerSize));
		} else { // Assume x86, meaning 4 bytes in size
			// Get the corresponding integer value
			nFunctionTab = getInt(pclntab.add(8));
			// Calculate the next offset
			offset = getInt(pclntab.add(8 + 2 * pointerSize));
			// Get the function name tab's address
			functionNameTab = pclntab.add(offset);
			// Calculate the next offset
			offset = getInt(pclntab.add(8 + 6 * pointerSize));
		}

		// Get the address of the function tab
		Address functionTab = pclntab.add(offset);
		// Declare and initiate a copy of the function tab
		Address p = functionTab;

		// Declare several variables for later use
		Address functionAddress;
		long functionDataOffset;
		Address namePointer;
		Address nameAddress;

		// Iterate over the number of functions in the tab
		for (int i = 0; i < nFunctionTab; i++) {
			// Check if the script's execution is cancelled
			if (monitor.isCancelled()) {
				// Break this loop, thus exiting the script's execution early
				break;
			}

			// If the pointer size is one of a x64 system
			if (pointerSize == POINTER_SIZE_X64) {
				// Get the function's address
				functionAddress = currentProgram.getAddressFactory().getAddress(Long.toHexString(getLong(p)).trim());
				// Adjust the offset
				p = p.add(pointerSize);
				// Get the function data's offset
				functionDataOffset = getLong(p);
			} else { // Assume x86, meaning 4 bytes in size
				// Get the function's address
				functionAddress = currentProgram.getAddressFactory().getAddress(Long.toHexString(getInt(p)).trim());
				// Adjust the offset
				p = p.add(pointerSize);
				// Get the function data's offset
				functionDataOffset = getInt(p);
			}
			// Move p to the next address
			p = p.add(pointerSize);
			// Get the function name pointer
			namePointer = functionTab.add(functionDataOffset + pointerSize);
			// Get the address of the function name, which is always 32 bits in size
			nameAddress = functionNameTab.add(getInt(namePointer));

			/*
			 * Create or rename the function at the address, with the name at the given
			 * address
			 */
			createOrRenameFunction(functionAddress, nameAddress);
		}
	}

	/**
	 * Recovers function names for functions in Golang version 1.18 and above
	 * 
	 * @param pclntab the start address of the pclntab
	 * @throws MemoryAccessException
	 * @throws AddressOutOfBoundsException
	 * @throws DuplicateNameException
	 * @throws InvalidInputException
	 */
	private void recoverFunctionNamesGo118Plus(Address pclntab)
			throws MemoryAccessException, AddressOutOfBoundsException, DuplicateNameException, InvalidInputException {
		// Get the pointer size
		byte pointerSize = getByte(pclntab.add(7));

		// Declare several variables
		long nFunctionTab;
		long textStart;
		long offset;
		Address functionNameTab;

		// Check if the pointer size matches a x64 system's pointer size
		if (pointerSize == POINTER_SIZE_X64) {
			// Get the number of functions tab address
			nFunctionTab = getLong(pclntab.add(8));
			// Get the start of the text
			textStart = getLong(pclntab.add(8 + 2 * pointerSize));
			// Calculate the next offset
			offset = getLong(pclntab.add(8 + 3 * pointerSize));
			// Get the address of the function name tab
			functionNameTab = pclntab.add(offset);
			// Calculate the next offset
			offset = getLong(pclntab.add(8 + 7 * pointerSize));
		} else { // Assume x86, meaning 4 bytes in size
			// Get the number of functions tab address
			nFunctionTab = getInt(pclntab.add(8));
			// Get the start of the text
			textStart = getInt(pclntab.add(8 + 2 * pointerSize));
			// Calculate the next offset
			offset = getInt(pclntab.add(8 + 3 * pointerSize));
			// Get the address of the function name tab
			functionNameTab = pclntab.add(offset);
			// Calculate the next offset
			offset = getInt(pclntab.add(8 + 7 * pointerSize));
		}

		// Get the address of the function tab
		Address functionTab = pclntab.add(offset);

		// Instantiate a copy of the function tab for later use
		Address p = functionTab;

		// Define the field size within the function tab, which is always 4
		int functabFieldSize = 4;

		// Declare several variables for later use
		Address functionAddress;
		int functionDataOffset;
		Address namePointer;
		Address nameAddress;

		// Iterate over all functions
		for (int i = 0; i < nFunctionTab; i++) {
			// Check if the script's execution is cancelled
			if (monitor.isCancelled()) {
				// Break this loop, thus exiting the script's execution early
				break;
			}

			// Get the address for the current function, which is always 32 bits in size
			functionAddress = currentProgram.getAddressFactory()
					.getAddress(Long.toHexString(getInt(p) + textStart).trim());
			// Adjust p
			p = p.add(functabFieldSize);

			// Get the function data offset
			functionDataOffset = getInt(p);
			// Adjust p
			p = p.add(functabFieldSize);
			// Get the pointer to the name
			namePointer = functionTab.add(functionDataOffset + functabFieldSize);
			// Get the pointer to the address, which is always 32 bits
			nameAddress = functionNameTab.add(getInt(namePointer));

			/*
			 * Create or rename the function at the address, with the name at the given
			 * address
			 */
			createOrRenameFunction(functionAddress, nameAddress);
		}
	}
}
