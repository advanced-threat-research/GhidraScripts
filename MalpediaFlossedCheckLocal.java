//A script to load the Malpedia FLOSSED JSON dataset, and compare it with the strings from the current program. Strings which aren't part of the Malpedia dataset are then printed out, as these are more likely to be unique to warrant interest.
//@author Max 'Libra' Kersten for Trellix
//@category
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.util.DefinedDataIterator;

public class MalpediaFlossedCheckLocal extends GhidraScript {

	/**
	 * The strings present within the current program
	 */
	private static List<String> STRINGS_FROM_CURRENT_PROGRAM;

	/**
	 * 
	 */
	private List<String> missingStrings;

	/**
	 * Defines if the case of the strings should be taken into account
	 */
	private boolean isCaseSensitive;

	/**
	 * The minimum length of a string, for it to be considered useful
	 */
	private static final int MINIMUM_STRING_LENGTH = 4;

	@Override
	protected void run() throws Exception {
		// Determine if case sensitivity is desired
		isCaseSensitive = askYesNo("Match strings case sensitive?",
				"Do you want the strings to be matched case sensitive?");

		// Obtain the JSON file's location
		File jsonFile = askFile("Select the extracted Malpedia FLOSS data set", "Select");

		// Initialise the missed strings list
		missingStrings = new ArrayList<>();

		// Get all strings from the currently open program
		STRINGS_FROM_CURRENT_PROGRAM = getStringsFromCurrentProgram(MINIMUM_STRING_LENGTH);

		// Parse the JSON file into a Java object
		MalpediaFlossed flossed = parse(jsonFile);

		// Print the about data from the JSON file
		printAbout(flossed.getAbout());

		// Get the mapping from the object
		Map<String, MalpediaFlossedString> flossedObject = flossed.getStringMapping();

		/*
		 * Create the message about the non-occurring strings, depending on the case
		 * sensitivity
		 */
		String message = "Strings not occurring in the Malpedia string set (this check is case ";
		if (isCaseSensitive == false) {
			message += "in";
		}
		message += "sensitive):";
		// Print said message
		println(message);

		/*
		 * Get a list of strings from the flossed object, since the keys are the
		 * strings. To easily iterate over the strings and to be able to fetch results,
		 * an ArrayList is used, rather than the set.
		 */
		List<String> stringKeys = new ArrayList<>(flossedObject.keySet());

		// Iterate over all strings within the current program
		for (int i = 0; i < STRINGS_FROM_CURRENT_PROGRAM.size(); i++) {
			// Get the current string
			String currentString = STRINGS_FROM_CURRENT_PROGRAM.get(i);
			// If the list of flossed strings does not contain the current string
			if (stringKeys.contains(currentString) == false) {
				// It is added to the list of missing strings
				missingStrings.add(currentString);
				// Printed for the analyst to see
				println("\t" + currentString);
			}
		}

		// If no missing strings were found, print a message related to that
		if (missingStrings.isEmpty()) {
			println("All strings of this binary occur within the Malpedia string set!");
		}

		/*
		 * If you want to print the matches for every file, and the top matches in
		 * descending order, use the commented code below.
		 */
//		Map<String, Integer> familyCountMapping = new HashMap<>();
//		for (Map.Entry<String, MalpediaFlossedString> entry : flossedObject.entrySet()) {
//			String key = entry.getKey();
//			MalpediaFlossedString value = entry.getValue();
//
//			println("Match found for \"" + key + "\"");
//			String message = "\tRelates to:\n";
//			List<String> familiesFromIds = getFamiliesByIds(flossed.getFamilyIdMapping(), value.getFamilies());
//			for (String family : familiesFromIds) {
//				message += "\t\t" + family + "\n";
//
//				if (familyCountMapping.containsKey(family)) {
//					Integer count = familyCountMapping.get(family);
//					count++;
//					familyCountMapping.put(family, count);
//				} else {
//					familyCountMapping.put(family, 1);
//				}
//			}
//			if (familiesFromIds.size() < 10) {
//				println(message);
//			}
//
//		}
//
//		Map<String, Integer> valuesDescending = familyCountMapping.entrySet().stream()
//				.sorted(Map.Entry.comparingByValue(Comparator.reverseOrder())).collect(Collectors.toMap(
//						Map.Entry::getKey, Map.Entry::getValue, (oldValue, newValue) -> oldValue, LinkedHashMap::new));
//
//		for (Map.Entry<String, Integer> entry : valuesDescending.entrySet()) {
//			println(entry.getKey() + " : " + entry.getValue());
//		}
//
//		println(valuesDescending.toString());
	}

	/**
	 * This is a helper function to get all families for a given ID, as a lookup for
	 * later use.
	 * 
	 * @param familyIdMapping The family-ID mapping
	 * @param ids             a list of IDs
	 * @return all matching families to all IDs
	 */
	private List<String> getFamiliesByIds(Map<Integer, String> familyIdMapping, List<Integer> ids) {
		Set<String> families = new HashSet<>();

		for (Integer id : ids) {
			if (familyIdMapping.containsKey(id)) {
				String family = familyIdMapping.get(id);
				families.add(family);
			}
		}

		List<String> output = new ArrayList<>(families);
		output.sort(String::compareToIgnoreCase);
		return output;
	}

	/**
	 * Prints the about message of the Malpedia data set
	 * 
	 * @param about the data set in Java object form
	 */
	private void printAbout(MalpediaFlossedAbout about) {
		println("About the Malpedia Flossed JSON data set:");
		println("\tAuthor:               " + about.getAuthor());
		println("\tDated flossed:        " + about.getDateFlossed());
		println("\tDate published:       " + about.getDatePublished());
		println("\tFLOSS version:        " + about.getFlossVersion());
		println("\tProcessed strings:    " + about.getNumberOfProcessedStrings());
		println("\tReference:            " + about.getReference());
		println("\tSource:               " + about.getSource());
		println();
	}

	/**
	 * Get all defined strings from the current program. Only strings equal to, or
	 * longer than, the given minimum size are returned
	 * 
	 * @param minimumLength the minimum length of the string to be included in the
	 *                      matches
	 * @return all strings that are at least as long as the minimum length
	 */
	private List<String> getStringsFromCurrentProgram(int minimumLength) {
		// Create a set to store all strings in
		Set<String> strings = new HashSet<>();

		// Get a data iterator
		DefinedDataIterator ddi = DefinedDataIterator.definedStrings(currentProgram);
		// Iterate over the data iterator
		for (Data d : ddi) {
			// Get an instance of the currently selected data
			StringDataInstance sdi = StringDataInstance.getStringDataInstance(d);
			// Get the string value of said string
			String s = sdi.getStringValue();

			// If the string is not null nor empty
			if (s != null && s.isEmpty() == false) {
				/*
				 * If the length of the string is equal to, or larger than the predefined
				 * minimum length
				 */
				if (s.length() >= minimumLength) {
					/*
					 * If there is no casing check, convert the string to lower case, for easier
					 * checking later on
					 */
					if (isCaseSensitive == false) {
						s = s.toLowerCase();
					}
					// Add the string to the set
					strings.add(s);
				}
			}
		}

		/*
		 * Sets do not contain duplicate items by their nature, but cannot always be
		 * accessed in the same way as a list can (i.e. when sorting, given the
		 * hashset's nature).
		 * 
		 * The unique strings from the list, are stored in a newly created array list,
		 * which maintains the order. Next, they are sorted alphabetically, ignoring the
		 * casing during sorting to avoid an order where A-Za-z would occur, but rather
		 * any casing of A through Z.
		 */
		List<String> output = new ArrayList<>(strings);
		output.sort(String::compareToIgnoreCase);
		return output;
	}

	/**
	 * A parsing function, which contains a custom GSON parser to properly parse the
	 * Malpedia JSON set
	 * 
	 * @param jsonFile the Malpedia JSON file, as a Java File object
	 * @return the custom Java object with all results
	 * @throws IOException
	 */
	private MalpediaFlossed parse(File jsonFile) throws IOException {
		/*
		 * Create a custom JSON deserializer
		 */
		JsonDeserializer<MalpediaFlossed> deserializer = new JsonDeserializer<MalpediaFlossed>() {
			@Override
			public MalpediaFlossed deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
					throws JsonParseException {
				JsonObject jsonObject = json.getAsJsonObject();

				Map<Integer, String> familyToIdMapping = new HashMap<>();
				JsonObject familyToIdJson = jsonObject.get("family_to_id").getAsJsonObject();
				Set<String> familyKeySet = familyToIdJson.keySet();
				for (String family : familyKeySet) {
					Integer value = familyToIdJson.get(family).getAsInt();
					familyToIdMapping.put(value, family);
				}

				JsonObject aboutJson = jsonObject.get("about").getAsJsonObject();
				String author = aboutJson.get("author").getAsString();
				String date_flossed = aboutJson.get("date_flossed").getAsString();
				String date_published = aboutJson.get("date_published").getAsString();
				String floss_version = aboutJson.get("floss_version").getAsString();
				String info = aboutJson.get("info").getAsString();
				String license = aboutJson.get("license").getAsString();
				int num_families = aboutJson.get("num_families").getAsInt();
				int num_processed_strings = aboutJson.get("num_processed_strings").getAsInt();
				int num_samples_flossed = aboutJson.get("num_samples_flossed").getAsInt();
				int num_total_strings = aboutJson.get("num_total_strings").getAsInt();
				String reference = aboutJson.get("reference").getAsString();
				String source = aboutJson.get("source").getAsString();

				MalpediaFlossedAbout about = new MalpediaFlossedAbout(author, date_flossed, date_published,
						floss_version, info, license, num_families, num_processed_strings, num_samples_flossed,
						num_total_strings, reference, source);

				Map<String, MalpediaFlossedString> stringMap = new HashMap<>();

				JsonObject stringsJson = jsonObject.get("strings").getAsJsonObject();
				Set<String> stringKeySet = stringsJson.keySet();

				// Iterate over all strings in the JSON file
				for (String string : stringKeySet) {
					// If a string does not match the minimum length, its omitted
					if (string.length() < MINIMUM_STRING_LENGTH) {
						continue;
					}

					// Declare a variable to store a copy of the string in
					String stringCopy;
					// Check if the copy of the string should be made lower case
					if (isCaseSensitive == false) {
						stringCopy = string.toLowerCase();
					} else {
						stringCopy = string;
					}

					/*
					 * If the current program's strings does not not contain this string, it is
					 * skipped. The non-matching strings aren't required, and parsing them will
					 * result in a long runtime of the script without any advantages. It also
					 * creates an out of heap space error within Ghidra, depending on how much
					 * memory one allocated to the JVM during startup.
					 */
					if (STRINGS_FROM_CURRENT_PROGRAM.contains(stringCopy) == false) {
						continue;
					}

					JsonObject stringJsonObject = stringsJson.get("string").getAsJsonObject();

					List<String> encodings = new ArrayList<>();
					JsonArray encodingsJson = stringJsonObject.get("encodings").getAsJsonArray();
					for (int i = 0; i < encodingsJson.size(); i++) {
						String encoding = encodingsJson.get(i).getAsString();
						encodings.add(encoding);
					}

					List<String> tags = new ArrayList<>();
					JsonArray tagsJson = stringJsonObject.get("tags").getAsJsonArray();
					for (int i = 0; i < tagsJson.size(); i++) {
						String tag = tagsJson.get(i).getAsString();
						tags.add(tag);
					}

					List<Integer> families = new ArrayList<>();

					JsonArray familiesJson = stringJsonObject.get("families").getAsJsonArray();
					for (int i = 0; i < familiesJson.size(); i++) {
						Integer family = familiesJson.get(i).getAsInt();
						families.add(family);
					}

					Integer familyCount = stringJsonObject.get("family_count").getAsInt();

					List<String> methods = new ArrayList<>();

					JsonArray methodsJson = stringJsonObject.get("methods").getAsJsonArray();
					for (int i = 0; i < methodsJson.size(); i++) {
						String method = methodsJson.get(i).getAsString();
						methods.add(method);
					}

					MalpediaFlossedString stringEntry = new MalpediaFlossedString(encodings, families, familyCount,
							methods, tags);
					stringMap.put(string, stringEntry);
				}

				return new MalpediaFlossed(about, familyToIdMapping, stringMap);
			}
		};

		// Read the file and store the result in a string
		String json = Files.readString(jsonFile.toPath());

		// Initialise the GSON builder
		GsonBuilder gsonBuilder = new GsonBuilder();

		// Register the custom deserializer
		gsonBuilder.registerTypeAdapter(MalpediaFlossed.class, deserializer);

		// Create a Gson instance, with the custom adapter type
		Gson customGson = gsonBuilder.create();

		// Parse the JSON into a Java object
		return customGson.fromJson(json, MalpediaFlossed.class);
	}

	private class MalpediaFlossed {
		private MalpediaFlossedAbout about;
		private Map<Integer, String> familyIdMapping;
		private Map<String, MalpediaFlossedString> stringMapping;

		public MalpediaFlossed(MalpediaFlossedAbout about, Map<Integer, String> familyIdMapping,
				Map<String, MalpediaFlossedString> stringMapping) {
			super();
			this.about = about;
			this.familyIdMapping = familyIdMapping;
			this.stringMapping = stringMapping;
		}

		public MalpediaFlossedAbout getAbout() {
			return about;
		}

		public Map<Integer, String> getFamilyIdMapping() {
			return familyIdMapping;
		}

		public Map<String, MalpediaFlossedString> getStringMapping() {
			return stringMapping;
		}
	}

	private class MalpediaFlossedString {
		private String string;
		private List<String> encodings;
		private List<Integer> families;
		private Integer familyCount;
		private List<String> methods;
		private List<String> tags;

		public MalpediaFlossedString() {

		}

		public MalpediaFlossedString(List<String> encodings, List<Integer> families, Integer familyCount,
				List<String> methods, List<String> tags) {
			super();
			this.encodings = encodings;
			this.families = families;
			this.familyCount = familyCount;
			this.methods = methods;
			this.tags = tags;
		}

		public List<String> getEncodings() {
			return encodings;
		}

		public List<Integer> getFamilies() {
			return families;
		}

		public Integer getFamilyCount() {
			return familyCount;
		}

		public List<String> getMethods() {
			return methods;
		}

		public List<String> getTags() {
			return tags;
		}
	}

	private class MalpediaFlossedAbout {
		private String author;
		private String dateFlossed;
		private String datePublished;
		private String flossVersion;
		private String info;
		private String license;
		private int numberOfFamilies;
		private int numberOfProcessedStrings;
		private int numberOfSamplesFlossed;
		private int numberOfTotalStrings;
		private String reference;
		private String source;

		public MalpediaFlossedAbout(String author, String dateFlossed, String datePublished, String flossVersion,
				String info, String license, int numberOfFamilies, int numberOfProcessedStrings,
				int numberOfSamplesFlossed, int numberOfTotalStrings, String reference, String source) {
			super();
			this.author = author;
			this.dateFlossed = dateFlossed;
			this.datePublished = datePublished;
			this.flossVersion = flossVersion;
			this.info = info;
			this.license = license;
			this.numberOfFamilies = numberOfFamilies;
			this.numberOfProcessedStrings = numberOfProcessedStrings;
			this.numberOfSamplesFlossed = numberOfSamplesFlossed;
			this.numberOfTotalStrings = numberOfTotalStrings;
			this.reference = reference;
			this.source = source;
		}

		public String getAuthor() {
			return author;
		}

		public String getDateFlossed() {
			return dateFlossed;
		}

		public String getDatePublished() {
			return datePublished;
		}

		public String getFlossVersion() {
			return flossVersion;
		}

		public String getInfo() {
			return info;
		}

		public String getLicense() {
			return license;
		}

		public int getNumberOfFamilies() {
			return numberOfFamilies;
		}

		public int getNumberOfProcessedStrings() {
			return numberOfProcessedStrings;
		}

		public int getNumberOfSamplesFlossed() {
			return numberOfSamplesFlossed;
		}

		public int getNumberOfTotalStrings() {
			return numberOfTotalStrings;
		}

		public String getReference() {
			return reference;
		}

		public String getSource() {
			return source;
		}
	}
}
