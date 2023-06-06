//Recovers Golang types within the given binary
//@author Max 'Libra' Kersten of Trellix' Advanced Research Center, based on the work by padorka@cujoai (https://github.com/getCUJO/ThreatIntel/blob/master/Scripts/Ghidra/type_extract.py)
//@category Golang
//@keybinding
//@menupath
//@toolbar

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

public class GolangTypeRecovery extends GhidraScript {

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
	 * The numeric value for the function kind, as defined in the Golang language
	 * specification
	 * 
	 * @see <a href="https://go.dev/src/reflect/type.go">The Golang source code for
	 *      the Type class, see the constant list under <code>type Kind uint</code>
	 *      for the complete list</a>
	 */
	private static final int KIND_FUNCTION = 0x13;

	/**
	 * The numeric value for the interface kind, as defined in the Golang language
	 * specification
	 * 
	 * @see <a href="https://go.dev/src/reflect/type.go">The Golang source code for
	 *      the Type class, see the constant list under <code>type Kind uint</code>
	 *      for the complete list</a>
	 */
	private static final int KIND_INTERFACE = 0x14;

	/**
	 * The numeric value for the pointer kind, as defined in the Golang language
	 * specification
	 * 
	 * @see <a href="https://go.dev/src/reflect/type.go">The Golang source code for
	 *      the Type class, see the constant list under <code>type Kind uint</code>
	 *      for the complete list</a>
	 */
	private static final int KIND_POINTER = 0x16;

	/**
	 * The numeric value for the struct kind, as defined in the Golang language
	 * specification
	 * 
	 * @see <a href="https://go.dev/src/reflect/type.go">The Golang source code for
	 *      the Type class, see the constant list under <code>type Kind uint</code>
	 *      for the complete list</a>
	 */
	private static final int KIND_STRUCT = 0x19;

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
	 * The human readable version strings that are to be used to determine the
	 * version of a Golang binary. These will be converted to byte strings during
	 * the script's runtime, and then stored in the {@link #versions} variable. The
	 * sole purpose of this additional step is to more easily update this script
	 * when fixing bugs and/or adding support for later Golang versions.
	 */
	private static final String[] HUMAN_READABLE_VERSIONS = { "go1.20", "go1.19", "go1.18", "go1.17", "go1.16",
			"go1.15", "go1.14", "go1.13", "go1.12", "go1.11", "go1.10", "go1.9", "go1.8", "go1.7", "go1.6", "go1.5",
			"go1.4", "go1.3", "go1.2" };

	/**
	 * Byte strings of the versions in the {@link #HUMAN_READABLE_VERSIONS}
	 * variable. This variable is to be initialised during runtime.
	 */
	private String[] versions;

	/**
	 * The Golang version of the analysed binary, stored globally for later use to
	 * avoid looking for the version multiple times. This value is one of the
	 * {@link #versions}, which is more easily read in its human readable format as
	 * defined within the {@link #HUMAN_READABLE_VERSIONS}.
	 */
	private String currentVersion;

	/**
	 * The magic values for the pclntab, as found in the Golang source code. Note
	 * that version <code>1.2</code> is less than <code>1.16</code>, since the value
	 * after the dot is to be seen as an incrementing value number, not as the usual
	 * mathematical way of writing. The values in the array are for the following
	 * Golang versions, in order:
	 * 
	 * <ol>
	 * <li>Version 1.2</li>
	 * <li>Version 1.16</li>
	 * <li>Version 1.18</li>
	 * <li>Version 1.20</li>
	 * </ol>
	 * 
	 * @see <a href="https://go.dev/src/debug/gosym/pclntab.go">Golang pclntab
	 *      source code</a>
	 */
	private static String[] pclntab_magic = { "\\xfb\\xff\\xff\\xff\\x00\\x00", "\\xfa\\xff\\xff\\xff\\x00\\x00",
			"\\xf0\\xff\\xff\\xff\\x00\\x00", "\\xf1\\xff\\xff\\xff\\x00\\x00" };

	/**
	 * The size of a pointer, in bytes, within the currently loaded binary
	 */
	private int binaryPointerSize;

	/**
	 * A hash set of addresses with recovered types, used to avoid recovering the
	 * same type twice.<br>
	 * <br>
	 * The hash set is used, instead of an {@link java.util.ArrayList}, as its more
	 * efficient. Both the {@link java.util.HashSet#contains(Object)} and
	 * {@link java.util.HashSet#add(Object)} methods function in <code>O(1)</code>,
	 * in contrast to the inner workings of other types, which often work in
	 * <code>O(n)</code>.<br>
	 * <br>
	 * Testing locally shows that the time to complete the script, on a test sample
	 * which contains 3047 to-be recovered types, is nearly three times as much when
	 * using an {@link java.util.ArrayList}, compared to the
	 * {@link java.util.HashSet}. The specifics obviously depend on the used
	 * hardware, but it shows that the hash set implementation is more efficient.
	 */
	private static HashSet<Address> recoveredTypes = new HashSet<>();

	/**
	 * The script's main function. This script can be executed normally and
	 * headless.
	 */
	@Override
	protected void run() throws Exception {
		// Initialise the byte string versions, based on the human readable ones
		versions = createVersionByteStrings();

		// Declares and initialises the executable format of the current program
		String executableFormat = currentProgram.getExecutableFormat();

		/*
		 * Initialises the global variable to store the pointer size of the currently
		 * analysed binary in
		 */
		binaryPointerSize = currentProgram.getDefaultPointerSize();

		// Optionally print the executable format
		log("Executable format: " + executableFormat);

		/*
		 * Defines the address array which is to be initialised differently, depending
		 * on the file's type
		 */
		Address[] objects;

		// If the file is of the PE format
		if (executableFormat.equalsIgnoreCase("Portable Executable (PE)")) {
			// Initialise the objects array
			objects = scanPeFile();
		} else if (executableFormat.equalsIgnoreCase("Executable and Linking Format (ELF)")) { // If the file is of the
																								// ELF format
			// Initialise the objects array
			objects = scanElfFile();
		} else {
			// Inform the analyst of the error
			printerr("Incorrect file format: \"" + executableFormat + "\"");
			// Exit the script
			return;
		}

		/*
		 * If the objects array is null, an error occurred earlier on, of which the
		 * analyst is already informed via an earlier printerr statement. As such, this
		 * function simply needs to return early to end the script's execution.
		 */
		if (objects == null) {
			return;
		}

		// Find the Golang version within the given binary
		currentVersion = findVersion();

		// Check if a version was found
		if (currentVersion == null) {
			// Inform the analyst of the failure to find a version
			printerr("No Golang version could be found in the binary!");
			// Return early as the version is required later on
			return;
		}

		/*
		 * Regardless if the file is of the PE or ELF format, the returned addresses are
		 * the same. As such, the array can be used in the same way. To easier read the
		 * function call, read it as:
		 * 
		 * getAllTypes(typelinks, endOfTypelinks, type);
		 */
		recoverAllTypes(objects[0], objects[1], objects[2]);

		// Print the number of recovered types for the analyst
		println("Types recovered: " + recoveredTypes.size());
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
	 * Gets the value of the bytes as a little endian short
	 * 
	 * @param bytes the value to read
	 * @return the value of the bytes as a little endian short
	 */
	private short getShort(byte[] bytes) {
		// Allocate a buffer of two bytes
		ByteBuffer buffer = ByteBuffer.allocate(2);
		// Set the order
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		// Place the first byte
		buffer.put(bytes[0]);
		// Place the second byte
		buffer.put(bytes[1]);
		// Get the value as a short, in little endian format
		return buffer.getShort(0);
	}

	/**
	 * Ingests the human readable versions and converts them into byte strings. The
	 * byte strings can be used to searched for using
	 * {@link #findBytes(Address, String)} and overloads thereof.<br>
	 * <br>
	 * An example of a byte string is <code>\xfb\xff\xff\xff\x00\x00</code>.
	 * 
	 * @return the byte strings of the given versions
	 */
	private String[] createVersionByteStrings() {
		// Declare and initialise the output variable
		String[] byteStrings = new String[HUMAN_READABLE_VERSIONS.length];

		// Loop over all human readable strings
		for (int i = 0; i < HUMAN_READABLE_VERSIONS.length; i++) {
			/*
			 * Convert each human readable string into a byte string, and store it in the
			 * output variable
			 */
			byteStrings[i] = createByteString(HUMAN_READABLE_VERSIONS[i]);
		}

		// Return the newly created byte strings
		return byteStrings;
	}

	/**
	 * Returns a byte string of the given string, assuming the given input is UTF-8
	 * encoded
	 * 
	 * @param input the UTF-8 encoded string
	 * @return a byte string of the given input
	 */
	private String createByteString(String input) {
		// Get the bytes from the given input
		byte[] bytes = input.getBytes(Charset.forName("UTF-8"));
		// Declare the byte string and initialise it as an empty string
		String byteString = "";

		// Iterate over all bytes
		for (byte currentByte : bytes) {
			// Get the current byte in string form
			String byteStringByte = Integer.toHexString(currentByte);

			/*
			 * If the length of the current string is only a single character, prepend a
			 * zero to ensure two digits are present for the given byte in string form
			 */
			if (byteStringByte.length() == 1) {
				byteStringByte = "0" + byteStringByte;
			}

			/*
			 * Prepend "\x" to byte string's current byte, which is then added to the
			 * complete byte string
			 */
			byteString += "\\x" + byteStringByte;
		}
		// Return the complete byte string
		return byteString;
	}

	/**
	 * Gets the address at the given address, essentially dereferencing the given
	 * pointer
	 * 
	 * @param address the address to dereference
	 * @return the dereferenced address
	 * @throws MemoryAccessException if the given address cannot be dereferenced
	 */
	private Address getAddressAt(Address address) throws MemoryAccessException {
		return toAddr(Long.toHexString(getInt(address)));
	}

	/**
	 * Removes data at the given location, which is required to retype certain
	 * variables
	 * 
	 * @param address the address to remove the type from
	 * @param length  the length of the data to remove the typing from
	 * @throws Exception if the address is invalid or null
	 */
	private void removeData(Address address, int length) throws Exception {
		// Iterate for the given length
		for (int i = 0; i < length; i++) {
			/*
			 * Remove the data at the given address plus the offset of the length, starting
			 * at 0
			 */
			removeDataAt(address.add(i));
		}
		// Return if no exception is thrown
	}

	/**
	 * Gets the sections that match (case insensitive) the given section name
	 * 
	 * @param sectionName the section name to match, matching is case insensitive
	 * @return the starting addresses of all sections which match the given section
	 *         name
	 */
	private Address[] getSection(String sectionName) {
		// Iterate over all memory blocks
		for (MemoryBlock block : getMemoryBlocks()) {
			// If the block's name matches the given section name, case insensitive
			if (block.getName().equalsIgnoreCase(sectionName)) {
				// Get the start of the block
				Address start = block.getStart();
				// Get the end of the block
				Address end = block.getEnd();
				/*
				 * Optionally print a message for the analyst with the block's name, start
				 * address, and end address
				 */
				log(String.format("%s [start: 0x%x, end: 0x%x]", block.getName(), start.getOffset(), end.getOffset()));
				// Return the start and end addresses
				return new Address[] { start, end };
			}
		}
		// Print a message for the analyst indicating the section couldn't be found
		printerr("Section \"" + sectionName + "\" not found!");
		// Return null in the case of an error
		return null;
	}

	/**
	 * Gets the start address for each section named <code>.typelink</code>
	 * 
	 * @return the start addresses for each section named <code>.typelink</code>
	 */
	private Address[] getTypeLink() {
		return getSection(".typelink");
	}

	/**
	 * Gets the start address for the <code>.rodata</code> section
	 * 
	 * @return the start address for the <code>.rodata</code> section
	 */
	private Address getRodata() {
		return getSection(".rodata")[0];
	}

	/**
	 * Returns the current version from any of the given versions, based on its
	 * presence in the binary. The first version that is found is used.
	 * 
	 * @return the byte string version that is found
	 */
	private String findVersion() {
		// Iterate over all versions in the global variable
		for (int i = 0; i < versions.length; i++) {
			// Declare a local variable for the currently iterated version
			String version = versions[i];

			// Find the address of the first occurrence of the current version
			Address[] addresses = findBytes(null, version, 1000);

			// Check if any results were found
			if (addresses == null || addresses.length == 0) {
				// If not, continue to the next attempt to find the version
				continue;
			}
			/*
			 * If the address is not null, inform the analyst with the human readable
			 * version, for all results
			 */
			for (Address address : addresses) {
				// Optionally print the Golang version
				log("Golang version found at 0x" + Long.toHexString(address.getOffset()) + " : "
						+ HUMAN_READABLE_VERSIONS[i]);
			}

			/*
			 * Return the current version based on the first match. This can be wrong, which
			 * is why all matches are printed to the analyst
			 */
			return version;
		}

		// Return null in the case of a failure to find the version
		return null;
	}

	/**
	 * Until and including Golang 1.16, the length offset was two bytes in size.
	 * From Golang 1.17 onwards, the length offset uses a variable length.<br>
	 * <br>
	 * For versions until and including 1.16, the second byte is used, which causes
	 * the script to potentially miss long strings.<br>
	 * <br>
	 * For versions 1.17 or later, the first byte is used, which causes the script
	 * to potentially miss long strings.
	 * 
	 * @return the length offset
	 */
	private int getLengthOffset() {
		/*
		 * Store the length of the current version byte string locally, which avoids
		 * calling the <code>length()<code> function several times
		 */
		int currentVersionLength = currentVersion.length();
		/*
		 * Get the first digit of the version (which is the one but last byte in the
		 * byte string), where the "1." part is omitted as its not required
		 */
		String firstDigit = currentVersion.substring(currentVersionLength - 6, currentVersionLength - 4);
		// Convert the value into a hexadecimal integer
		int integer = Integer.parseInt(firstDigit, 16);
		// Convert the value into a character
		char c = (char) integer;

		/*
		 * Declare and initialise the variable to store the version number in, in string
		 * format
		 */
		String versionNumberString = "" + c;

		/*
		 * Get the last digit of the version (which is the one but last byte in the byte
		 * string), where the "1." part is omitted as its not required
		 */
		String lastDigit = currentVersion.substring(currentVersionLength - 2, currentVersionLength);
		// Convert the value into a hexadecimal integer
		integer = Integer.parseInt(lastDigit, 16);
		// Convert the value into a character
		c = (char) integer;
		// Append the number
		versionNumberString = versionNumberString + c;

		// Convert the version number into an integer
		int versionNumber = Integer.parseInt(versionNumberString);

		// Compare the version to the versions of 1.17 or later
		if (versionNumber >= 17) {
			// Return one, as only one byte will be used
			return 1;
		}

		/*
		 * If none of the >= 1.17 versions matches, assume the version is lower than
		 * that, and thus the second byte is used
		 */
		return 2;
	}

	/**
	 * Looks for the pclntab within the binary, without looking for a section with
	 * the same name, but rather for a magic value within the binary
	 * 
	 * @param pclntab_magic the byte strings of pclntab magic strings to look for
	 * @return Returns an object array where the pclntab address is at index 0, and
	 *         the matching magic byte string is at index 1. The magic value can be
	 *         null!
	 * @throws MemoryAccessException if the pclntab memory cannot be accessed
	 */
	private Object[] findPclntabPE() throws MemoryAccessException {
		// Iterate over all plcntab magic byte strings
		for (String magic : pclntab_magic) {
			// Search through the program for the given byte string
			Address[] results = findBytes(null, magic, 1000);

			// Ensure the results are not null nor empty
			if (results == null || results.length == 0) {
				// If no matches are found, continue
				continue;
			}

			// Iterate over all results
			for (int i = 0; i < results.length; i++) {
				// Get the currently iterated address
				Address tempAddress = results[i];

				// If the returned value is not found
				if (tempAddress == null) {
					// Move to the next result in the address array
					continue;
				}
				// Check if the match is aligned with the pclntab structure
				if (isPclntab(tempAddress)) {
					// Optionally inform the analyst of the finding
					log("pclntab found!");
					// Return the pclntab's address and the respective magic value
					return new Object[] { tempAddress, magic };
				}
			}
		}
		// If nothing can be found, inform the analyst and then return null
		printerr("The pclntab could not be found!");
		return null;
	}

	/**
	 * Checks if the given address matches the pclntab structure pattern
	 * 
	 * @param address the address to check
	 * @return true if the structure matches, false if not
	 * @throws MemoryAccessException if the memory at the given address (and a few
	 *                               bytes more) cannot be accessed
	 */
	private boolean isPclntab(Address address) throws MemoryAccessException {
		// Get the PC Quantum Size value
		byte pcQuantum = getByte(address.add(6));
		// Get the pointer size from the binary
		byte pclntabPointerSize = getByte(address.add(7));
		// Verify the validity of the values
		if ((pcQuantum != INSTRUCTION_SIZE_ONE && pcQuantum != INSTRUCTION_SIZE_TWO
				&& pcQuantum != INSTRUCTION_SIZE_FOUR)
				|| (pclntabPointerSize != POINTER_SIZE_X86 && pclntabPointerSize != POINTER_SIZE_X64)) {
			// Return false if the conditions aren't met
			return false;
		}
		// Return true if the conditions are met
		return true;
	}

	/**
	 * Checks if the given address is the start of the module data
	 * 
	 * @param address the address to check
	 * @param magic   the magic value of the module data from the pclntab
	 * @return true if the given address is the address of the module data, false if
	 *         not
	 * @throws MemoryAccessException if the memory at the given address, and offsets
	 *                               thereof, aren't accessible for any reason
	 */
	private boolean isModuleData(Address address, String magic) throws MemoryAccessException {
		// Declare the offset
		int offset;

		/*
		 * Check if the magic value of Golang version 1.2 is in-use, as the offset
		 * differs in this case
		 */
		if (magic.equalsIgnoreCase("\\xfb\\xff\\xff\\xff\\x00\\x00")) { // Golang version 1.2 magic value
			offset = 12;
		} else {
			offset = 22;
		}

		// Get the text address based on the given address and the offset
		Address text = getAddressAt(address.add(offset * binaryPointerSize));

		// Get the memory block that corresponds with the .text section
		MemoryBlock textBlock = currentProgram.getMemory().getBlock(".text");

		/*
		 * Verify the module data by ensuring the offset from the module data matches
		 * the offset of the .text block
		 */
		if (text != null && text.getOffset() == textBlock.getStart().getOffset()) {
			log("Module data found!");
			return true;
		}

		// Return false if the offset does not match, or if there is no .text section
		return false;
	}

	/**
	 * Finds the address of the module data, based on the given pclntab address and
	 * the pclntab magic value
	 * 
	 * @param pclntab the address of the pclntab
	 * @param magic   the magic value of the pclntab
	 * @return the address of the module data
	 * @throws MemoryAccessException if the pclntab, or offsets thereof, aren't
	 *                               accessible for any reason
	 */
	private Address findModuleData(Address pclntab, String magic) throws MemoryAccessException {
		// Declare the module data address
		Address moduleData;
		// Get all references to the pclntab
		Reference[] pclntabReferences = getReferencesTo(pclntab);

		// Iterate over all references
		for (Reference reference : pclntabReferences) {
			// Get the reference-making address
			moduleData = reference.getFromAddress();
			// Check if the address matches the module data structure
			if (isModuleData(moduleData, magic)) {
				// Optionally print the module data's address
				log("Module data address: " + moduleData.toString(false, true));
				// Return the address once a match is found
				return moduleData;
			}
		}

		/*
		 * If no such reference was found, a search through the whole program is to be
		 * started for the usage of the pclntab address, which is referenced in the
		 * module data. Searching only through specific sections is possible, but since
		 * this function is only called once in the beginning, and the improved accuracy
		 * outweighs the marginally extra time that is required
		 */

		/*
		 * Create a string of the inverted and hexadecimal representation of the pclntab
		 * address
		 */
		String invertedHexPclntab = Long.toHexString(Long.reverseBytes(pclntab.getOffset()));

		/*
		 * If the binary size is four, the string needs to be 8 characters long (four
		 * times two characters, meaning four time two bytes).
		 */
		if (binaryPointerSize == 4) {
			invertedHexPclntab = invertedHexPclntab.substring(0, 8);
		}
		/*
		 * If the pointer size is not four, its assumed to be eight, which is the
		 * default value of the long representation already, meaning no change has to be
		 * made
		 */
		String byteStringPclntab = "";

		// Iterate over all characters, in sets of two per iteration
		for (int i = 0; i < invertedHexPclntab.length(); i = i + 2) {
			// Create the byte in string form, which is appended to the byte string variable
			byteStringPclntab += "\\x" + invertedHexPclntab.charAt(i) + invertedHexPclntab.charAt(i + 1);
		}

		/*
		 * Get all results for the given byte string, starting at the program's
		 * beginning
		 */
		Address[] results = findBytes(null, byteStringPclntab, 1000);

		// If the results are null or empty, return early
		if (results != null && results.length > 0) {
			// Iterate over all results
			for (int i = 0; i < results.length; i++) {
				// Temporarily store the current result in the module data variable
				moduleData = results[i];

				// Check if the current address is the start of the module data structure
				if (isModuleData(moduleData, magic)) {
					// Return the value if that is the case
					return moduleData;
				}
			}
		}
		// Inform the analyst of the missing value
		printerr("The module data cannot be found!");
		// Return null if no match is found
		return null;
	}

	/**
	 * Gets the typeStart, typeEnd, typeLinks, and numberOfTypes variables based on
	 * the given module data address and the plcntab magic value.<br>
	 * <br>
	 * Returns an array of objects which contains the following types and values, in
	 * order:<br>
	 * <ol>
	 * <li>Address typeStart</li>
	 * <li>Address typeEnd</li>
	 * <li>Address typeLinks</li>
	 * <li>int numberOfTypes</li>
	 * </ol>
	 * 
	 * @param moduleData  the address of the module data
	 * @param magic       the plcntab magic value
	 * @param pointerSize the size of the pointer in bytes
	 * @return in order Address type, Address etype, Address typelinks, int ntypes
	 * @throws MemoryAccessException if the value at the module data address, or
	 *                               offsets thereof, cannot be accessed for any
	 *                               reason
	 */
	private Object[] getTypeLinks(Address moduleData, String magic) throws MemoryAccessException {
		// Declaration of the two offsets
		int offset;
		int offset2;

		// The offsets differ in Golang 1.2
		if (magic.equalsIgnoreCase("\\xfb\\xff\\xff\\xff\\x00\\x00")) { // Golang 1.2 magic value
			offset = 25;
			offset2 = 30;
		} else {
			offset = 35;
			offset2 = 42;
		}

		// Get the required values
		Address typeStart = getAddressAt(moduleData.add(offset * binaryPointerSize));
		Address typeEnd = getAddressAt(moduleData.add((offset + 1) * binaryPointerSize));
		Address typeLinks = getAddressAt(moduleData.add(offset2 * binaryPointerSize));
		int numberOfTypes = getInt(moduleData.add((offset2 + 1) * binaryPointerSize));

		// Return the values in an object array
		return new Object[] { typeStart, typeEnd, typeLinks, numberOfTypes };
	}

	/**
	 * Recover the types, based on the type's address and the type's location
	 * 
	 * @param typeAddress
	 * @param type
	 * @return
	 * @throws Exception
	 */
	private Address recoverTypes(Address typeAddress, Address type) throws Exception {
		try {
			// Check if the type is already recovered
			if (recoveredTypes.contains(typeAddress)) {
				// If the type is already recovered, optionally notify the analyst
				log(String.format("Type already recovered at  0x%x", typeAddress.getOffset()));
				// Return the type's address
				return typeAddress;
			}

			// Gets the length offset
			int lengthOffset = getLengthOffset();

			// Add the current type to the list of recovered types
			recoveredTypes.add(typeAddress);

			// Declare and initialise the temporary offset variable
			int tempOffset = 2 * binaryPointerSize + 4;
			// Declare and initialise the temporary address
			Address tempAddress = typeAddress.add(tempOffset);

			// Get the byte at the given address
			byte b = getByte(tempAddress);

			// Declare and initialise the uncommon flag
			byte tflagUncommon = (byte) (b & 0x01);

			// Get the byte for the extra star flag
			b = getByte(typeAddress.add(2 * binaryPointerSize + 4));

			// Declare and initialise the extra star far
			byte tflagExtraStar = (byte) (b & 0x02);

			// Get the byte for the kind
			b = getByte(typeAddress.add(2 * binaryPointerSize + 7));

			// Declare and initialise the kind
			byte kind = (byte) (b & 0x1F);

			// Get the type name offset
			int nameOffset = getInt(typeAddress.add(4 * binaryPointerSize + 8));

			// Get the type name length
			byte nameLength = getByte(type.add(nameOffset + lengthOffset));

			// Get the name's address
			Address nameAddress = type.add(nameOffset + lengthOffset + 1);

			// Remove the data type(s) from the given addresses
			removeData(nameAddress, nameLength);

			// Create an ASCII string at the given address with the given length
			Data name = createAsciiString(nameAddress, nameLength);

			// Declare the variable
			String nameType;

			// Get the type's name
			if (tflagExtraStar == 1) {
				nameType = ((String) name.getValue()).substring(1);
			} else {
				nameType = ((String) name.getValue());
			}

			// Optionally print the name of the type
			log("Recovered: \"" + nameType + "\"");

			// Create a label at the given address for the given name, excluding spaces
			createLabel(typeAddress, nameType.replace(" ", "_"), true);

			/*
			 * The function type (funcType) is structured as shown below. More information
			 * can be found here: https://go.dev/src/reflect/type.go
			 *
			 * struct {
			 * 
			 * funcType uncommonType
			 * 
			 * [2]*rtype // [0] is in, [1] is out
			 * 
			 * }
			 * 
			 * type funcType struct {
			 * 
			 * rtype
			 * 
			 * inCount uint16
			 * 
			 * outCount uint16 //the top bit is set if it is the last input parameter
			 * 
			 * }
			 */
			if (kind == KIND_FUNCTION) {
				byte[] bytes = getBytes(typeAddress.add(4 * binaryPointerSize + 8 + 8), 2);
				short inCount = getShort(bytes);

				byte[] outBytes = getBytes(typeAddress.add(4 * binaryPointerSize + 8 + 8 + 2), 2);
				// the top bit is set if it is the last input parameter
				int lastInput = outBytes[1] & 0x80;
				outBytes[1] = (byte) (outBytes[1] & 0x7F);
				int outCount = getShort(outBytes);

				List<String> inputs = new ArrayList<>();
				List<String> outputs = new ArrayList<>();

				for (int i = 0; i < inCount; i++) {
					Address input = getAddressAt(typeAddress.add(4 * binaryPointerSize + 8 + 8 + binaryPointerSize
							+ tflagUncommon * 16 + i * binaryPointerSize));
					recoverTypes(input, type);
					inputs.add(getSymbolAt(input).getName());
				}

				for (int i = 0; i < outCount; i++) {
					Address output = getAddressAt(typeAddress.add(4 * binaryPointerSize + 8 + 8 + binaryPointerSize
							+ tflagUncommon * 16 + inCount * binaryPointerSize + i * binaryPointerSize));
					recoverTypes(output, type);
					outputs.add(getSymbolAt(output).getName());
				}

				if (lastInput == 0x80 && inputs.size() > 0) {
					String comment = "func(";
					for (String string : inputs) {
						comment += string + ", ";
					}
					comment = comment.substring(0, comment.length() - 2);
					comment += ") (";

					for (String string : outputs) {
						comment += string + ", ";
					}
					comment = comment.substring(0, comment.length() - 2) + ")";
					setPreComment(typeAddress, comment);
				}
			}

			/*
			 * Interface type interfaceType represents an interface type.
			 * 
			 * type interfaceType struct {
			 * 
			 * rtype pkgPath name // import path methods
			 * 
			 * []imethod // sorted by hash
			 * 
			 * }
			 * 
			 * method represents a method on an interface type
			 * 
			 * type imethod struct {
			 * 
			 * name nameOff // name of method
			 * 
			 * typ typeOff // .(*FuncType) underneath
			 * 
			 * }
			 */
			if (kind == KIND_INTERFACE) {
				Address imethodField = getAddressAt(typeAddress.add(5 * binaryPointerSize + 8 + 8));
				List<String> methods = new ArrayList<>();
				int methodLength = getInt(typeAddress.add(6 * binaryPointerSize + 8 + 8));

				for (int i = 0; i < methodLength; i++) {
					int imethodNameOffset = getInt(imethodField);
					nameLength = getByte(type.add(imethodNameOffset + lengthOffset));
					nameAddress = type.add(imethodNameOffset + lengthOffset + 1);
					removeData(nameAddress, nameLength);
					name = createAsciiString(nameAddress, nameLength);
					String temp = (String) name.getValue();
					setEOLComment(imethodField, temp);
					createLabel(imethodField, temp.replace(" ", "_"), true);
					int newTypeOffset = getInt(imethodField.add(4));
					Address newType = type.add(newTypeOffset);
					recoverTypes(newType, type);
					imethodField = imethodField.add(8);
					methods.add(name.getValue() + " " + getSymbolAt(newType).getName());
					String comment = "type " + nameType + " interface{" + "\n\t" + "\n\t";
					for (int j = 0; j < methods.size(); j++) {
						comment += methods.get(j) + "\n\t";
					}
					comment += "\n" + "}";
					setPreComment(typeAddress, comment);
				}
			}

			/*
			 * Pointer type is used to represent a pointer type
			 * 
			 * type ptrType struct {
			 * 
			 * rtype
			 * 
			 * elem *rtype // pointer element (pointed at) type
			 * 
			 * 
			 * }
			 */
			if (kind == KIND_POINTER) {
				Address newAddress = toAddr(
						Integer.toHexString(getInt(typeAddress.add(4 * binaryPointerSize + 8 + 8))));
				recoverTypes(newAddress, type);
			}

			/*
			 * Struct type structType represents a struct type.
			 * 
			 * type structType struct {
			 * 
			 * rtype
			 * 
			 * pkgPath name
			 * 
			 * fields []structField // sorted by offset
			 * 
			 * }
			 * 
			 * Struct field
			 * 
			 * type structField struct {
			 * 
			 * name name // name is always non-empty
			 * 
			 * typ *rtype // type of field
			 * 
			 * offsetEmbed uintptr // byte offset of field<<1 | isEmbedded
			 * 
			 * }
			 */
			if (kind == KIND_STRUCT) {
				Address structField = getAddressAt(typeAddress.add(5 * binaryPointerSize + 8 + 8));
				List<String> fields = new ArrayList<>();
				int fieldLength = getInt(typeAddress.add(6 * binaryPointerSize + 8 + 8));
				for (int i = 0; i < fieldLength; i++) {
					Address structFieldName = getAddressAt(structField);
					Address nameLengthAddress = structFieldName.add(lengthOffset);
					nameLength = getByte(nameLengthAddress);
					nameAddress = getAddressAt(structField).add(lengthOffset + 1);
					removeData(nameAddress, nameLength);
					name = createAsciiString(nameAddress, nameLength);
					String temp = (String) name.getValue();
					setEOLComment(structField, temp);
					createLabel(structFieldName, temp.replace(" ", "_"), true);
					Address newType = getAddressAt(structField.add(binaryPointerSize));
					structField = structField.add(3 * binaryPointerSize);
					fields.add(name.getValue() + " " + getSymbolAt(newType).getName());

					String comment = "type " + nameType + " struct{" + "\n\t" + "\n\t";
					for (int j = 0; j < fields.size(); j++) {
						comment += fields.get(j) + "\n\t";
					}
					comment += "\n" + "}";

					setPreComment(typeAddress, comment);
				}
			}
		} catch (Exception ex) {
			// Ignore errors
		}
		return null;
	}

	/**
	 * Fetches the typeLinksStart, typeLinksEnd, and typeStart addresses from the
	 * binary if it is a PE file.<br>
	 * <br>
	 * Returns an array of Address objects which contains the following values, in
	 * order:<br>
	 * <ol>
	 * <li>typeLinksStart</li>
	 * <li>typeLinksEnd</li>
	 * <li>typeStart</li>
	 * </ol>
	 * 
	 * @param pclntab_magic the potential magic values for the pclntab
	 * @return the typeLinksStart, typeLinksEnd, and typeStart addresses
	 * @throws MemoryAccessException if memory within the binary, or offsets
	 *                               thereof, cannot be properly accessed
	 */
	private Address[] scanPeFile() throws MemoryAccessException {
		// Searches for the pclntab in a PE file
		Object[] pclntabArray = findPclntabPE();

		/*
		 * If the pclntab cannot be found, the analyst is informed in the called
		 * function. Simply return null in order for the script to return back to the
		 * main function, which will return early if null is encountered.
		 */
		if (pclntabArray == null) {
			return null;
		}

		// Saves the results in two variables
		Address pclntab = (Address) pclntabArray[0];
		String magic = (String) pclntabArray[1];

		// Searches for the module data
		Address moduleData = findModuleData(pclntab, magic);

		/**
		 * Similar to the missing pclntab, if the module data cannot be found, the
		 * analyst is informed in the called function, and null is to be handed to the
		 * caller which ensures execution ends early.
		 */
		if (moduleData == null) {
			return null;
		}

		// Save the results in four variables
		Object[] typeLinksArray = getTypeLinks(moduleData, magic);
		Address typeStart = (Address) typeLinksArray[0];
		// Address typeEnd = (Address) typeLinksArray[1];
		Address typeLinksStart = (Address) typeLinksArray[2];
		int numberOfTypes = (int) typeLinksArray[3];

		// Calculate the end of the type links section
		Address typeLinksEnd = typeLinksStart.add(numberOfTypes * 4);

		// Return all addresses in an array
		return new Address[] { typeLinksStart, typeLinksEnd, typeStart };
	}

	/**
	 * Fetches the typeLinksStart, typeLinksEnd, and typeStart addresses from the
	 * binary if it is an ELF file.<br>
	 * <br>
	 * Returns an array of Address objects which contains the following values, in
	 * order:<br>
	 * <ol>
	 * <li>typeLinksStart</li>
	 * <li>typeLinksEnd</li>
	 * <li>typeStart</li>
	 * </ol>
	 * 
	 * @param pclntab_magic the potential magic values for the pclntab
	 * @return the typelinks start, the typelinks end (plus one byte), and type
	 *         start address
	 */
	private Address[] scanElfFile() {
		// Get the type link array
		Address[] typeLinkArray = getTypeLink();
		// Get the read-only data section
		Address typeStart = getRodata();

		/*
		 * If either the type link or read-only sections cannot be found, the analyst is
		 * informed and null is returned by the respective function. To cut the
		 * execution short, this function simply returns null to its caller.
		 */
		if (typeLinkArray == null || typeStart == null) {
			return null;
		}

		// Store the start and end in two variables
		Address typelinksStart = typeLinkArray[0];
		Address typeLinksEnd = typeLinkArray[1];
		typeLinksEnd = typeLinksEnd.add(1);

		// Return the values in an array
		return new Address[] { typelinksStart, typeLinksEnd, typeStart };
	}

	/**
	 * Recovers all types present within the program
	 * 
	 * @param typeLinksStart the start of the typelinks
	 * @param typeLinksEnd   the end of the typelinks plus one byte
	 * @param type           the start of the types
	 * @throws Exception if something goes wrong
	 */
	private void recoverAllTypes(Address typeLinksStart, Address typeLinksEnd, Address type) {
		// Ensure the type link is not null
		if (typeLinksStart != null) {
			// Declare and initialise a copy of the start address
			Address p = typeLinksStart;
			// Iterate until the end of the type links section is reached
			while (p.compareTo(typeLinksEnd) <= 0) {
				// Check if the script's execution is cancelled
				if (monitor.isCancelled()) {
					// Break this loop, thus exiting the script's execution early
					break;
				}

				try {
					// Get the type offset by dereferencing the address pointer
					int typeOffset = getInt(p);
					// Get the type address based on the offset
					Address typeAddress = type.add(typeOffset);
					// Recover the types for the given address
					recoverTypes(typeAddress, type);
				} catch (Exception ex) {
					// Ignore exceptions
				}
				// Increment the address
				p = p.add(4);
			}
		}
	}
}
