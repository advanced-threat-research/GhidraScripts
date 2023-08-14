//Runs SHAREM and gets the resulting output, which is then annotated within Ghidra. This fixes dissassembly mistakes, adds context and arguments to function calls, and creates data points.
//@author Trellix (by Max ' Libra' Kersten)
//@category shellcode analysis
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.util.Arrays;

import com.google.gson.Gson;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Data;

public class Sharem extends GhidraScript {

	@Override
	protected void run() throws Exception {
		// The directory in which the command is executed, to be edited prior to using the script
		File workingDirectory = new File("C:\\path\\to\\sharem");
		// The command to execute within said working directory, to be edited prior to using the script
		String command = "C:\\path\\to\\python.exe main.py [architecture as in -r32 or -r64] C:\\path\\to\\shellcode.bin";

		try {
			/*
			 * Executes the given command from within the given working directory. This
			 * function only returns once the command has been executed.
			 */
			execute(workingDirectory, command);
		} catch (Exception ex) {
			// Print the error message
			printerr(ex.getMessage());
			// Return early
			return;
		}

		// Instantiate a new Gson object for later use
		Gson gson = new Gson();

		// Declare the JSON file variable, based on the working directory
		File jsonFile = new File(
				workingDirectory.getAbsolutePath() + "\\sharem\\sharem\\sharem\\logs\\default\\jsondefaultdisasm.json");

		// Read the file and store the result in a string
		String json = Files.readString(jsonFile.toPath());

		// Convert the raw JSON into a Java object
		SharemObject result = gson.fromJson(json, SharemObject.class);

		// Iterate over the objects
		for (SharemSubObject object : result.getObjects()) {
			// If a given object's comment is not null, empty, nor white space
			if (object.getComment().isBlank() == false) {
				// Get the offset in hexadecimal format
				long offset = Long.parseLong(object.getAddress().substring(2), 16);
				// Set a comment at the given offset, with the given comment
				setPreComment(toAddr(offset), object.getComment());
				// Create a string to print debug information
				String message = "Commented \"" + object.getComment() + "\" at " + object.getAddress();
				// Print the message
				println(message);
			}

			// If the type is CODE
			if (object.getBytes().equalsIgnoreCase("CODE")) {
				// Get the value of the bytes
				byte[] sharemValues = getBytesFromSharemObject(object);
				if (sharemValues == null) {
					continue;
				}
				// Get the bytes from Ghidra's listing
				byte[] ghidraValues = getBytes(toAddr(object.getAddress()), object.getSize());
				// If the values aren't equal
				if (Arrays.compare(sharemValues, ghidraValues) > 0) {
					// Clear the listing
					clearListing(toAddr(object.getAddress()));
					// Set the bytes as provided by SHAREM
					setBytes(toAddr(object.getAddress()), sharemValues);
					// Disassemble the bytes
					disassemble(toAddr(object.getAddress()));
				}
			} else if (object.getBytes().equalsIgnoreCase("DATA")) { // If the type is DATA
				if (object.getDataType().equalsIgnoreCase("String")) { // if the type is a string
					// Get the data at the given address
					Data data = getDataAt(toAddr(object.getAddress()));
					// If the data is not null
					if (data != null) {
						// Compare the length of the data and the size mentioned in the SHAREM object
						if (data.getLength() != object.getSize()) {
							// Get the end address
							Address end = toAddr(object.getAddress()).add(toAddr(object.getSize()).getOffset() - 1);
							// Get the start address
							Address start = toAddr(object.getAddress());
							// Clear the listing
							clearListing(start, end);
							// Create a string at the given address
							createAsciiString(toAddr(object.getAddress()));
						}
					} else {
						// Get the end address
						Address end = toAddr(object.getAddress()).add(toAddr(object.getSize()).getOffset() - 1);
						// Get the start address
						Address start = toAddr(object.getAddress());
						// Clear the listing
						clearListing(start, end);
						// If no data is present, simply create a string at the address
						createData(toAddr(object.getAddress()), StringDataType.dataType);
					}
				} else if (object.getDataType().equalsIgnoreCase("API Pointer")) { // If the type is a pointer
					// Get the data at the address
					Data data = getDataAt(toAddr(object.getAddress()));
					// If the data is not present
					if (data == null) {
						// Create the pointer
						createData(toAddr(object.getAddress()), PointerDataType.dataType);
					}
					// Set a comment with the instruction to provide context
					setPreComment(toAddr(object.getAddress()), object.getInstruction());
				} else if (object.getDataType().equalsIgnoreCase("DATA")) {
					// Get the data at the address
					Data data = getDataAt(toAddr(object.getAddress()));
					
					/*
					 * If the data is not null, it exists, and can thus be removed, since it will be
					 * overwritten
					 */
					if (data != null) {
						// Get the end address
						Address end = toAddr(object.getAddress()).add(toAddr(object.getSize()).getOffset() - 1);
						// Get the start address
						Address start = toAddr(object.getAddress());
						// Clear the listing
						clearListing(start, end);
					}

					// Handle different sizes with regards to data creation
					switch (object.getSize()) {
					case 1:
						createData(toAddr(object.getAddress()), ByteDataType.dataType);
						break;
					case 2:
						createData(toAddr(object.getAddress()), WordDataType.dataType);
						break;
					case 4:
						createData(toAddr(object.getAddress()), DWordDataType.dataType);
						break;
					case 8:
						createData(toAddr(object.getAddress()), QWordDataType.dataType);
						break;
					}

				}
			}
		}
	}

	/**
	 * A helper function to get the bytes from the given disassembly object's hex
	 * value field which contains the instruction in hexadecimal format
	 * 
	 * @param object the disassembly object
	 * @return the raw bytes of the given instruction, if any
	 */
	private byte[] getBytesFromSharemObject(SharemSubObject object) {
		byte[] bytes = new byte[object.getSize()];
		String[] values = object.getHex().split(" ");

		for (int i = 0; i < values.length; i++) {
			try {
				bytes[i] = (byte) Integer.parseInt(values[i], 16);
			} catch (Exception ex) {
				/*
				 * Ignore entries where the value ends with dots, as those aren't hex values.
				 * Returning null ensures the caller to omit these bytes
				 */
				return null;
			}

		}
		return bytes;
	}

	/**
	 * Determines if the current operating system is Windows.
	 *
	 * @return true if the operating system is Windows, false if it is not.
	 */
	public static boolean isWindows() {
		/*
		 * If the os.name property of the Java VM contains "windows", the system is
		 * Windows based
		 */
		if (System.getProperty("os.name").toLowerCase().contains("windows")) {
			return true;
		}
		return false;
	}

	/**
	 * A helper function to launch a new process via the system's shell
	 * 
	 * @param workingDirectory the working directory of the process
	 * @param command          the command to execute
	 * @throws Exception if anything goes wrong
	 */
	public void execute(File workingDirectory, String command) throws Exception {
		try {
			String[] processName = new String[1];
			// Check if the OS is windows
			if (isWindows()) {
				processName[0] = "cmd";
			} else { // Use the shell if the OS is not Windows
				processName[0] = "sh";
			}
			// Start a new shell
			Process p = Runtime.getRuntime().exec(processName, null, workingDirectory);
			// Get the standard input
			PrintWriter stdin = new PrintWriter(p.getOutputStream());
			// Start the command via the shell
			stdin.println(command);
			// Close the stream
			stdin.close();
			// Wait until the process terminates
			p.waitFor();
		} catch (Exception ex) {
			/*
			 * Throw an exception if anything goes wrong, which is used to notify the
			 * analyst
			 */
			throw new Exception("Error while launching SHAREM! Error:\n\n" + ex.getMessage());
		}
	}

	class SharemSubObject {

		/**
		 * The starting address within the binary where the reference to is made
		 */
		private String address;

		/**
		 * The instruction, as extracted by SHAREM
		 */
		private String instruction;

		/**
		 * The hex value of the instruction
		 */
		private String hex;

		/**
		 * The size of the object (i.e. the length of a string, or the size of an
		 * instruction)
		 */
		private String size;

		/**
		 * Is either <code>CODE</code> or <code>DATA</code>, indicating what the type of
		 * the object is
		 */
		private String bytes;

		/**
		 * Provides further information about the data type, if this object references
		 * DATA. The optional values are <code>String</code> or <code>API Pointer</code>
		 */
		private String dataType;

		/**
		 * Defines how data is accessed
		 */
		private String dataAccessed;

		/**
		 * Gets the string representation of the data (at the given address with the
		 * given length). This can be garbage when not dealing with strings (i.e.
		 * instructions)
		 */
		private String string;

		/**
		 * Gets a SHAREM made comment for this object
		 */
		private String comment;

		/**
		 * A label which contains an address, if present. Redundant field.
		 */
		private String label;

		/**
		 * Creates an instance of a single instruction/piece of data that is emitted by
		 * SHAREM.
		 * 
		 * @param address      the starting address within the binary where the
		 *                     reference to is made
		 * @param instruction  the instruction, as extracted by SHAREM
		 * @param hex          the hex value of the instruction
		 * @param size         the size of the object (i.e. the length of a string, or
		 *                     the size of an instruction)
		 * @param bytes        is either <code>CODE</code> or <code>DATA</code>,
		 *                     indicating what the type of the object is
		 * @param dataType     provides further information about the data type, if this
		 *                     object references DATA. The optional values are
		 *                     <code>String</code> or <code>API Pointer</code>
		 * @param dataAccessed defines how data is accessed
		 * @param string       gets the string representation of the data (at the given
		 *                     address with the given length). This can be garbage when
		 *                     not dealing with strings (i.e. instructions)
		 * @param comment      gets a SHAREM made comment for this object
		 * @param label        a label which contains an address, if present. Redundant
		 *                     field.
		 */
		public SharemSubObject(String address, String instruction, String hex, String size, String bytes,
				String dataType, String dataAccessed, String string, String comment, String label) {
			this.address = address;
			this.instruction = instruction;
			this.hex = hex;
			this.size = size;
			this.bytes = bytes;
			this.dataType = dataType;
			this.dataAccessed = dataAccessed;
			this.string = string;
			this.comment = comment;
			this.label = label;
		}

		/**
		 * The starting address within the binary where the reference to is made
		 * 
		 * @return the address as a string
		 */
		public String getAddress() {
			return address;
		}

		/**
		 * The instruction, as extracted by SHAREM
		 * 
		 * @return the instruction as a string
		 */
		public String getInstruction() {
			return instruction;
		}

		/**
		 * The hex value of the instruction
		 * 
		 * @return the hex value as a string (split by spaces, not denoted by "0x")
		 */
		public String getHex() {
			return hex;
		}

		/**
		 * The size of the object (i.e. the length of a string, or the size of an
		 * instruction)
		 * 
		 * @return the size as a string
		 */
		public int getSize() {
			return Integer.parseInt(size);
		}

		/**
		 * Is either <code>CODE</code> or <code>DATA</code>, indicating what the type of
		 * the object is
		 * 
		 * @return the type, as a string
		 */
		public String getBytes() {
			return bytes;
		}

		/**
		 * Provides further information about the data type, if this object references
		 * DATA. The optional values are <code>String</code> or <code>API Pointer</code>
		 * 
		 * @return the more granular type, as a string
		 */
		public String getDataType() {
			return dataType;
		}

		/**
		 * Defines how data is accessed
		 * 
		 * @return the way the data is accessed, as a string
		 */
		public String getDataAccessed() {
			return dataAccessed;
		}

		/**
		 * Gets the string representation of the data (at the given address with the
		 * given length). This can be garbage when not dealing with strings (i.e.
		 * instructions)
		 * 
		 * @return the value of the object
		 */
		public String getString() {
			return string;
		}

		/**
		 * Gets a SHAREM made comment for this object
		 * 
		 * @return the comment
		 */
		public String getComment() {
			return comment;
		}

		/**
		 * A label which contains an address, if present. Redundant field.
		 * 
		 * @return the label as a string
		 */
		public String getLabel() {
			return label;
		}
	}

	/**
	 * The JSON output from SHAREM is an array of items. For ease-of-access and
	 * ease-of-handling, a Java class is used as a wrapper around the array
	 * 
	 * @author Max 'Libra' Kersten for Trellix
	 *
	 */
	class SharemObject {

		/**
		 * The array of entries from SHAREM
		 */
		private SharemSubObject[] disassembly;

		/**
		 * Creates an instance of this wrapper object
		 * 
		 * @param disassembly the array of objects which contain the disassembly of the
		 *                    analysed shellcode
		 */
		public SharemObject(SharemSubObject[] disassembly) {
			this.disassembly = disassembly;
		}

		/**
		 * Gets the SHAREM objects
		 * 
		 * @return the SHAREM objects
		 */
		public SharemSubObject[] getObjects() {
			return disassembly;
		}
	}
}
