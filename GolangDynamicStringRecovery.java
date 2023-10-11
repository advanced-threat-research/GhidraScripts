//Finds and creates dynamically allocated strings based on the Golang stringStruct 
//@author Max 'Libra' Kersten of Trellix' Advanced Research Center, based on the work by padorka@cujoai (https://github.com/getCUJO/ThreatIntel/blob/master/Scripts/Ghidra/find_dynamic_strings.py)
//@category Golang
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;

public class GolangDynamicStringRecovery extends GhidraScript {

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
	 * The size of a pointer on X86
	 */
	private static final int POINTER_SIZE_X86 = 4;

	/**
	 * The size of a pointer on X64
	 */
	private static final int POINTER_SIZE_X64 = 8;

	/**
	 * The number of recovered dynamic strings
	 */
	private static int stringCount = 0;

	@Override
	protected void run() throws Exception {
		/*
		 * Get the language ID and the program's pointer size and store those locally,
		 * as they are re-used multiple times
		 */
		String languageId = currentProgram.getLanguageID().toString();
		int pointerSize = currentProgram.getDefaultPointerSize();

		/*
		 * Based on the language ID, the dynamic strings need to be recovered
		 * differently
		 */
		if (languageId.startsWith("ARM")) { // 32-bit ARM
			resolve32BitArm();
		} else if (languageId.startsWith("AARCH64")) { // 64-bit ARM
			resolve64BitArm();
		} else if (languageId.startsWith("x86") && pointerSize == POINTER_SIZE_X86) { // x86
			resolveIntel(false);
		} else if (languageId.startsWith("x86") && pointerSize == POINTER_SIZE_X64) { // x86_64
			resolveIntel(true);
		} else { // Print an error message if the architecture is not supported
			printerr("Unsupported architecture: " + languageId);
			return;
		}

		// Print the total number of recovered strings
		println("Total number of recovered dynamic strings: " + stringCount);
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
	 * Creates an ASCII string at the given address with the given length, and
	 * returns the instruction after the given instruction
	 * 
	 * @param instruction the current instruction within the program
	 * @param address     the address of the ASCII string
	 * @param length      the length of the ASCII string
	 * @return the instruction after the instruction variable, or null if there is
	 *         no such instruction
	 */
	private Instruction createString(Instruction instruction, Address address, Integer length) {
		try {
			//Get the data' starting point
			Data checkData = getDataContaining(address);
			if (checkData != null) {
				clearListing(address);
				
			}
			// Create the ASCII string at the given address with the given length
			Data data = createAsciiString(address, length);
			// Gets the newly created string as a String object
			String ascii = (String) data.getValue();
			// Optionally print the address (clickable in Ghidra's console) along with the
			// value
			log("0x" + Long.toHexString(address.getOffset()) + " : \"" + ascii + "\"");
			// Increment the number of recovered dynamic strings
			stringCount++;
		} catch (Exception ex) {
			// Ignore exceptions
		}
		// Return the next instruction
		return getInstructionAfter(instruction);
	}

	/**
	 * This helper function returns the integer value of a scalar object. The
	 * purpose of this function is to avoid repeated casting in numerous places
	 * within the script.
	 * 
	 * @param scalar the object to get the integer value from
	 * @return the integer value of the given scalar object
	 */
	private Integer getInteger(Scalar scalar) {
		return ((Long) scalar.getValue()).intValue();
	}

	/**
	 * Gets all memory blocks which have a name equal to .text or __text (used in PE
	 * and ELF, and Mach-O files respectively), disregarding the used casing. The
	 * list can be empty, but never null.
	 * 
	 * @return all .text or __text named memory blocks (used in PE and ELF, and
	 *         Mach-O files respectively), disregarding the used casing
	 */
	private List<MemoryBlock> getTextMemoryBlocks() {
		// Declare and initialise the list
		List<MemoryBlock> blocks = new ArrayList<>();

		// Iterate over all blocks
		for (MemoryBlock block : getMemoryBlocks()) {
			// Check if the name is equal, disregarding the case
			if (block.getName().equalsIgnoreCase(".text") || block.getName().equalsIgnoreCase("__text")) {
				// If it is equal, add it to the list
				blocks.add(block);
			}
		}
		// Return the list, which might be empty
		return blocks;
	}

	/**
	 * Resolves the dynamic strings for Intel architecture based binaries. This
	 * works for both x86 and x86_64 architectures
	 * 
	 * @param is64Bit true if the given binary is 64-bit, false if not
	 */
	private void resolveIntel(boolean is64Bit) {
		// Iterate over all memory blocks
		for (MemoryBlock block : getTextMemoryBlocks()) {
			// Get the first instruction from this block
			Instruction instruction = getInstructionAt(block.getStart());

			// Loop as long as an instruction is present and valid
			while (instruction != null) {
				// Check if the script's execution is cancelled
				if (monitor.isCancelled()) {
					// Return from the recovery function, thus exiting the script's execution early
					return;
				}

				try {
					// Get the operand type at index 1, which should be an address
					int operandType = instruction.getOperandType(1);
					// Get the register at index zero
					Register register = instruction.getRegister(0);

					/*
					 * Check the first instruction of a dynamically allocated string:
					 * 
					 * LEA REG, [STRING_ADDRESS]
					 * 
					 * This is the same for x86 and x86_64, hence no bitness check
					 */
					if (instruction.getMnemonicString().equalsIgnoreCase("LEA") == false || register == null
							|| OperandType.isAddress(operandType) == false) {
						// Get the next instruction
						instruction = getInstructionAfter(instruction);
						// Skip this item in the loop
						continue;
					}

					// Get the next instruction
					Instruction instructionTwo = getInstructionAfter(instruction);

					/*
					 * Check the second instruction:
					 * 
					 * MOV [SP + ..], REG
					 * 
					 * Note that the stack pointer is either ESP or RSP, depending on the
					 * architecture (x86 or x86_64 respectively)
					 * 
					 * Also note that REG refers to the same register as the first instruction used
					 * 
					 * The is64Bit boolean is true if the used architecture is x86_64, false if it
					 * is x86
					 */
					if (instructionTwo.getMnemonicString().equalsIgnoreCase("MOV") == false
							|| instructionTwo.getRegister(1) != register) {
						if ((is64Bit == false
								&& instructionTwo.getOpObjects(0)[0].toString().equalsIgnoreCase("ESP") == false)
								|| (is64Bit == true && instructionTwo.getOpObjects(0)[0].toString()
										.equalsIgnoreCase("RSP") == false)) {
							// Get the next instruction
							instruction = getInstructionAfter(instruction);
							// Skip this item in the loop
							continue;
						}
					}

					// Get the third instruction
					Instruction instructionThree = getInstructionAfter(instructionTwo);

					/*
					 * Get the operand type (should be a scalar) at index one of the third
					 * instruction
					 */
					operandType = instructionThree.getOperandType(1);

					/*
					 * Look for the third instruction, which follows either of the following
					 * patterns, depending on the architecture:
					 * 
					 * MOV [ESP + ..], STRING_SIZE
					 * 
					 * MOV [RSP + ..], STRING_SIZE
					 * 
					 * Note that the operand type should be of the scalar type
					 * 
					 * The is64Bit boolean is true if the used architecture is x86_64, false if it
					 * is x86
					 */
					if (instructionThree.getMnemonicString().equalsIgnoreCase("MOV") == false
							|| OperandType.isScalar(operandType) == false) {
						if ((is64Bit == false
								&& instructionThree.getOpObjects(0)[0].toString().equalsIgnoreCase("ESP") == false)
								|| (is64Bit == true && instructionThree.getOpObjects(0)[0].toString()
										.equalsIgnoreCase("RSP") == false)) {
							// Get the next instruction
							instruction = getInstructionAfter(instruction);
							// Skip this item in the loop
							continue;
						}
					}

					// Get the address
					Address address = instruction.getPrimaryReference(1).getToAddress();
					/*
					 * Get the instruction's first indexed object, of which the first element (index
					 * 0) is used
					 */
					Object object = instructionThree.getOpObjects(1)[0];

					// Check if the object is of the scalar type
					if (object instanceof Scalar == false) {
						// Get the next instruction
						instruction = getInstructionAfter(instruction);
						// Skip this item in the loop
						continue;
					}

					/*
					 * This code can only be reached if the object's type is scalar, so it can
					 * safely be cast
					 */
					Scalar scalar = (Scalar) object;
					// Get the integer value of the scalar object
					Integer lengthValue = getInteger(scalar);
					/*
					 * Create a string at the given address with the given length, and increment to
					 * the next instruction
					 */
					instruction = createString(instruction, address, lengthValue);
				} catch (Exception ex) {
					// Get the next instruction
					instruction = getInstructionAfter(instruction);
					// Skip this item in the loop
					continue;
				}
			}
		}
	}

	/**
	 * Resolves the dynamic strings for 32-bit ARM architecture based binaries
	 */
	private void resolve32BitArm() {
		/*
		 * #ARM, 32-bit
		 * 
		 * #LDR REG, [STRING_ADDRESS_POINTER]
		 * 
		 * #STR REG, [SP, ..]
		 * 
		 * #MOV REG, STRING_SIZE
		 * 
		 * #STR REG, [SP, ..]
		 */
		// Iterate over all memory blocks
		for (MemoryBlock block : getTextMemoryBlocks()) {
			// Get the first instruction
			Instruction instruction = getInstructionAt(block.getStart());

			// Loop as long as an instruction is present and valid
			while (instruction != null) {
				// Check if the script's execution is cancelled
				if (monitor.isCancelled()) {
					// Return from the recovery function, thus exiting the script's execution early
					return;
				}

				try {
					// Get the operand type, which should be an address or a scalar
					int operandType = instruction.getOperandType(1);

					// Check first instruction: LDR REG, [STRING_ADDRESS_POINTER]
					if (instruction.getMnemonicString().equalsIgnoreCase("ldr") == false
							|| instruction.getRegister(0) == null || OperandType.isAddress(operandType) == false
							|| OperandType.isScalar(operandType) == false) {
						// Get the next instruction
						instruction = getInstructionAfter(instruction);
						// Skip this item in the loop
						continue;
					}

					// Get the register at index 0
					Register register = instruction.getRegister(0);
					// Get the second instruction
					Instruction instructionTwo = getInstructionAfter(instruction);

					/*
					 * Check second instruction:
					 * 
					 * STR REG, [SP + ..]
					 * 
					 * Note that the register REG should be the same as the register that was used
					 * in the first instruction
					 */
					if (instructionTwo.getMnemonicString().equalsIgnoreCase("str") == false
							|| instructionTwo.getRegister(0) != register
							|| instructionTwo.getOpObjects(1)[0].toString().equalsIgnoreCase("sp") == false) {
						// Get the next instruction
						instruction = getInstructionAfter(instruction);
						// Skip this item in the loop
						continue;
					}

					// Get the third instruction
					Instruction instructionThree = getInstructionAfter(instructionTwo);
					// Get the operand type, which should be a scalar
					operandType = instructionThree.getOperandType(1);

					// Check third instruction: MOV REG, STRING_SIZE
					if (instructionThree.getMnemonicString().equalsIgnoreCase("mov") == false
							|| instructionThree.getRegister(0) == null || OperandType.isScalar(operandType) == false) {
						// Get the next instruction
						instruction = getInstructionAfter(instruction);
						// Skip this item in the loop
						continue;
					}

					// Get the first register from the third instruction
					register = instructionThree.getRegister(0);
					// Get the first instruction
					Instruction instructionFour = getInstructionAfter(instructionThree);

					/*
					 * Check fourth instruction:
					 * 
					 * STR REG, [SP + ..]
					 * 
					 * Note that the register REG should be the same register that was used in the
					 * third instruction
					 */
					if (instructionFour.getMnemonicString().equalsIgnoreCase("str") == false
							|| instructionFour.getRegister(0) != register
							|| instructionFour.getOpObjects(1)[0].toString().equalsIgnoreCase("sp") == false) {
						// Get the next instruction
						instruction = getInstructionAfter(instruction);
						// Skip this item in the loop
						continue;
					}

					// Get the address pointer
					int addressPointer = getInt(instruction.getPrimaryReference(1).getToAddress());
					// Get the address, essentially dereferencing the pointer
					Address address = currentProgram.getAddressFactory().getAddress(Long.toHexString(addressPointer));

					// Get the second object (index 1) from the third instruction
					Object object = instructionThree.getOpObjects(1)[0];
					// Check if the object is of the scalar type
					if (object instanceof Scalar == false) {
						// Get the next instruction
						instruction = getInstructionAfter(instruction);
						// Skip this item in the loop
						continue;
					}
					/*
					 * This code is only reachable if the object is of the scalar type, so it can be
					 * cast
					 */
					Scalar scalar = (Scalar) object;
					// Get the scalar's value as an integer
					Integer length = getInteger(scalar);
					/*
					 * Create the ASCII string at the given address for the given length, along with
					 * the next instruction
					 */
					instruction = createString(instruction, address, length);
				} catch (Exception ex) {
					// Ignore exceptions
				}
			}
		}
	}

	/*
	 * Resolves the dynamic strings for 64-bit ARM architecture based binaries
	 */
	private void resolve64BitArm() {
		/*
		 * #ARM, 64-bit - version 1
		 * 
		 * #ADRP REG, [STRING_ADDRESS_START]
		 * 
		 * #ADD REG, REG, INT
		 * 
		 * #STR REG, [SP, ..]
		 * 
		 * #ORR REG, REG, STRING_SIZE
		 * 
		 * #STR REG, [SP, ..]
		 * 
		 * #ARM, 64-bit - version 2
		 *
		 * #ADRP REG, [STRING_ADDRESS_START]
		 *
		 * #ADD REG, REG, INT
		 *
		 * #STR REG, [SP, ..]
		 *
		 * #MOV REG, STRING_SIZE
		 *
		 * #STR REG, [SP, ..]
		 */

		// Iterate over all memory blocks
		for (MemoryBlock block : getTextMemoryBlocks()) {
			// Get the first instruction from this block
			Instruction instruction = getInstructionAt(block.getStart());

			// Loop as long as an instruction is present and valid
			while (instruction != null) {
				// Check if the script's execution is cancelled
				if (monitor.isCancelled()) {
					// Return from the recovery function, thus exiting the script's execution early
					return;
				}

				// Get the operand type at index 1, which should be a scalar
				int operandType = instruction.getOperandType(1);
				// Get the register at index zero
				Register register = instruction.getRegister(0);

				/*
				 * Check first instruction of a dynamically allocated string
				 * 
				 * ADRP REG, [STRING_ADDRESS_START]
				 */
				if (instruction.getMnemonicString().equalsIgnoreCase("adrp") == false
						|| instruction.getRegister(0) == null || OperandType.isAddress(operandType) == false
						|| OperandType.isScalar(operandType) == false) {
					// Get the next instruction
					instruction = getInstructionAfter(instruction);
					// Skip this item in the loop
					continue;
				}

				// Get the second instruction
				Instruction instructionTwo = getInstructionAfter(instruction);
				/*
				 * Get the operand type of the second instruction at index 2, which should be of
				 * the scalar type
				 */
				operandType = instructionTwo.getOperandType(2);

				/*
				 * Check second instruction:
				 * 
				 * ADD REG, REG, INT
				 * 
				 * Note that REG refers to the same register as the first instruction used
				 * 
				 * Also note that the operand type needs to be of the scalar type
				 */
				if (instructionTwo.getMnemonicString().equalsIgnoreCase("add") == false
						|| instructionTwo.getRegister(0) != register || OperandType.isScalar(operandType) == false) {
					// Get the next instruction
					instruction = getInstructionAfter(instruction);
					// Skip this item in the loop
					continue;
				}

				// Get the third instruction
				Instruction instructionThree = getInstructionAfter(instructionTwo);

				/*
				 * Check the third instruction:
				 * 
				 * STR REG, [SP + ..]
				 * 
				 * Note that REG refers to the same register as the first instruction used
				 */
				if (instructionThree.getMnemonicString().equalsIgnoreCase("str") == false
						|| instructionThree.getRegister(0) != register
						|| instructionThree.getOpObjects(1)[0].toString().equalsIgnoreCase("sp") == false) {
					// Get the next instruction
					instruction = getInstructionAfter(instruction);
					// Skip this item in the loop
					continue;
				}

				// Get the fourth instruction
				Instruction instructionFour = getInstructionAfter(instructionThree);
				// Get the register from the fourth instruction, at index 0
				register = instructionFour.getRegister(0);

				/*
				 * Declare several variables, which are to be initialised at a later stage,
				 * depending on the way it is loaded (version 1 or version 2)
				 */
				int length;
				Object object;
				Scalar scalar;

				/*
				 * Check fourth instruction:
				 * 
				 * Version 1: ORR REG, REG, STRING_SIZE
				 * 
				 * Version 2: MOV REG, STRING_SIZE
				 * 
				 * Note that the operand type needs to be a scalar
				 * 
				 * Also note that the register from the fourth instruction should not be null
				 */
				if (instructionFour.getMnemonicString().equalsIgnoreCase("orr") == false && register != null
						&& OperandType.isScalar(instructionFour.getOperandType(2)) == true) {
					// Get the relevant object
					object = instructionFour.getOpObjects(2)[0];
					/*
					 * The relevant object is of the scalar type, as defined within the if-statement
					 */
					scalar = (Scalar) object;
					// Get the scalar's value as an integer
					length = getInteger(scalar);
				} else if (instructionFour.getMnemonicString().equalsIgnoreCase("mov") && register != null
						&& OperandType.isScalar(instructionFour.getOperandType(1)) == true) {
					// Get the relevant object
					object = instructionFour.getOpObjects(1)[0];
					/*
					 * The relevant object is of the scalar type, as defined within the if-statement
					 */
					scalar = (Scalar) object;
					// Get the scalar's value as an integer
					length = getInteger(scalar);
				} else {
					// Get the next instruction
					instruction = getInstructionAfter(instruction);
					// Skip this item in the loop
					continue;
				}

				// Gets the fifth instruction
				Instruction instructionFive = getInstructionAfter(instructionFour);

				/*
				 * Check fifth instruction:
				 * 
				 * STR REG, [SP + ..]
				 * 
				 * Note that REG refers to the same register as the fourth instruction used
				 */
				if (instructionFive.getMnemonicString().equalsIgnoreCase("str") == false
						|| instructionFive.getRegister(0) != register
						|| instructionFive.getOpObjects(1)[0].toString().equalsIgnoreCase("sp") == false) {
					// Get the next instruction
					instruction = getInstructionAfter(instruction);
					// Skip this item in the loop
					continue;
				}
				// Get two objects
				Object objA = instruction.getOpObjects(1)[0];
				Object objB = instructionTwo.getOpObjects(2)[0];

				// Ensure that both objects are of the scalar type
				if (objA instanceof Scalar == false || objB instanceof Scalar == false) {
					// Gets the next instruction
					instruction = getInstructionAfter(instruction);
					// Skip this item in the loop
					continue;
				}

				// Cast the object to the correct type if this code is reached
				scalar = (Scalar) objA;
				// Get the scalar's value as an integer
				Integer addressPointer = getInteger(scalar);

				// Cast the object to the correct type if this code is reached
				scalar = (Scalar) objB;

				/*
				 * Get the scalar's value as an integer. Note the "+=" instead of "="
				 */
				addressPointer += getInteger(scalar);

				// Dereference the pointer
				Address address = currentProgram.getAddressFactory().getAddress(Long.toHexString(addressPointer));

				/*
				 * Create the ASCII string at the given address for the given length, along with
				 * the next instruction
				 */
				instruction = createString(instruction, address, length);
			}
		}
	}
}
