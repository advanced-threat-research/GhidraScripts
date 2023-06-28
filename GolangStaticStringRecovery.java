//Finds and creates statically allocated strings based on the Golang stringStruct 
//@author Max 'Libra' Kersten of Trellix' Advanced Research Center, based on the work by padorka@cujoai (https://github.com/getCUJO/ThreatIntel/blob/master/Scripts/Ghidra/find_static_strings.py)
//@category Golang
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

public class GolangStaticStringRecovery extends GhidraScript {
	
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
	 * The size of a pointer on X64
	 */
	private static final int POINTER_SIZE_X64 = 8;

	/*
	 * #x86
	 * 
	 * #LEA REG, [STRING_ADDRESS]
	 * 
	 * #MOV [ESP + ..], REG
	 * 
	 * #MOV [ESP + ..], STRING_SIZE
	 */

	@Override
	protected void run() throws Exception {
		// Declare and initialise the number of recovered static strings
		int stringCount = 0;

		/*
		 * Store the imagebase's offset and the pointer size as they are reused multiple
		 * times
		 */
		long imageBaseOffset = currentProgram.getImageBase().getOffset();
		int pointerSize = currentProgram.getDefaultPointerSize();

		// Iterate over all memory blocks
		for (MemoryBlock block : getMemoryBlocks()) {
			/*
			 * If the block name is not .data or .rodata, it can be skipped, as static
			 * strings are only present in the data sections
			 */
			if (block.getName().equalsIgnoreCase(".data") == false
					&& block.getName().equalsIgnoreCase(".rodata") == false) {
				continue;
			}

			// Get the start of the block
			Address blockStart = block.getStart();
			// Get the end of the block
			Address blockEnd = block.getEnd();

			/*
			 * Run as long as the start is less than, or equal to the end address, thus
			 * ensuring the whole block is iterated over
			 */
			while (blockStart.compareTo(blockEnd) <= 0) {
				// Check if the script's execution is cancelled
				if (monitor.isCancelled()) {
					// Return from the run function, thus exiting the script's execution early
					return;
				}

				// Declare the string address variable
				Address stringAddress;

				// Declare and initialises the variable
				Address stringAddressPointer = blockStart;

				// Get the length address
				Address lengthAddress = blockStart.add(pointerSize);

				// Increment the start of the block
				blockStart = blockStart.add(pointerSize);

				/*
				 * The next segment of the code is within a try-catch structure. The reason for
				 * this is simple: the static string recovery strategy does not work in all
				 * cases. An exception is simply ignored, as the catch segment simply continues
				 * to the next step. Since the start of the block is compared to the end of the
				 * block, the whole section is iterated over, meaning that any error just moves
				 * over to the next piece of memory within the block.
				 */
				try {
					// Declare the length variable
					long length;

					// Check if the pointer size matches a x64 pointer's size
					if (pointerSize == POINTER_SIZE_X64) {
						// Get the long value at the given address
						length = getLong(lengthAddress);
					} else { // Assume the binary is x86
						// Get the integer value at the given address
						length = getInt(lengthAddress);
					}

					/*
					 * To avoid false positives, strings which have no length, or are longer than
					 * 100 characters, are considered incorrect and thus skipped
					 */
					if (length <= 0 || length > 100) {
						continue;
					}

					// Check if the pointer size matches a x64 pointer's size
					if (pointerSize == POINTER_SIZE_X64) {
						// Get the long at the given string address pointer
						stringAddress = currentProgram.getAddressFactory()
								.getAddress(Long.toHexString(getLong(stringAddressPointer)));
					} else {// Assume the binary is x86
						// Get the integer at the given string address pointer
						stringAddress = currentProgram.getAddressFactory()
								.getAddress(Long.toHexString(getInt(stringAddressPointer)));
					}

					/*
					 * If the address offset is less than the image base offset, the current attempt
					 * is faulty and needs to be skipped
					 */
					if (stringAddress.getOffset() < imageBaseOffset) {
						continue;
					}

					/*
					 * Check if the string is printable. If it is not, the current address needs to
					 * be skipped
					 */
					if (isPrintable(stringAddress, length) == false) {
						continue;
					}

					// Create a pointer to the string
					createData(stringAddressPointer, PointerDataType.dataType);

					// Get the length
					Data data = getDataAt(lengthAddress);

					/*
					 * If there is no data type defined at the given address, it needs to be created
					 */
					if (data == null) {
						data = createData(lengthAddress, IntegerDataType.dataType);
					}

					// Get the type of the data
					DataType dataType = data.getDataType();
					// Get the name of the data type
					String dataTypeName = dataType.getName();

					/*
					 * If the data type is an undefined type of 4 or 8 bytes in size, it is to be
					 * removed, as a new type is to be set
					 */
					if (dataTypeName.equalsIgnoreCase("undefined4") || dataTypeName.equalsIgnoreCase("undefined8")) {
						removeData(getDataAt(lengthAddress));
					}

					// Create an integer at the given address
					createData(lengthAddress, IntegerDataType.dataType);

					/*
					 * Create the ASCII string at the given address with the given length (cast to a
					 * boxed long to use the intValue function)
					 */
					Data stringData = createAsciiString(stringAddress, ((Long) length).intValue());

					// Get the string value as a string
					String string = (String) stringData.getValue();

					// Optionally pPrint the location and the string value for the user
					log("0x" + Long.toHexString(stringAddress.getOffset()) + " : \"" + string + "\"");

					// Increment the number of recovered strings
					stringCount++;
				} catch (Exception e) {
					/*
					 * Exceptions are bound to happen due to some of the what more crude approaches,
					 * but they can simply be skipped
					 */
					continue;
				}
			}
		}

		// Inform the analyst of the number of recovered strings
		println("Total number of recovered static strings: " + stringCount);
	}

	/**
	 * Checks if a string, starting at the given address with the given length, is
	 * printable. Printable in this context means that the value of each byte of the
	 * string is between 32 and 126
	 * 
	 * @param start  the address of the start of the string
	 * @param length the length of the string
	 * @return true if the complete string is printable, false if not
	 * @throws MemoryAccessException
	 */
	private boolean isPrintable(Address start, long length) throws MemoryAccessException {
		// Iterate over the complete string
		for (int i = 0; i < length; i++) {
			// Get the current byte
			byte b = getByte(start);
			// Check the byte's value
			if (b < 32 || b > 126) {
				// If any of the bytes has the wrong value, return false early
				return false;
			}
			// Increment the string's address by one
			start = start.add(1);
		}
		/*
		 * If the early return isn't hit and the complete string has been iterated over,
		 * it means the complete string is printable, thus true needs to be returned
		 */
		return true;
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
}
