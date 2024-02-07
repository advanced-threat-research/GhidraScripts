//A script to query the Malpedia FLOSSED JSON dataset via the web API (hosted by Malpedia, or a local instance) and compare it with the strings from the current program. Strings which aren't part of the Malpedia dataset are then printed out, as these are more likely to be unique to warrant interest.
//@author Max 'Libra' Kersten for Trellix
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Type;
import java.net.HttpURLConnection;
import java.net.URL;
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

public class MalpediaFlossedCheckWebApi extends GhidraScript {

	/**
	 * The URL to the API. Change this if you are self hosting an instance of this
	 * service, otherwise the public Malpedia instance will be used.
	 */
	private static final String WEB_API_URL = "https://strings.malpedia.io/api/query/";

	/**
	 * The minimum length of a string, for it to be considered useful
	 */
	private int MINIMUM_STRING_LENGTH;

	@Override
	protected void run() throws Exception {
		// Get the minimum string length from the user or the CLI in headless mode
		MINIMUM_STRING_LENGTH = askInt("Minimum string length",
				"What is the minimum length of a given string to be submitted to the web service? Any value lower than four will result in the value of four.");

		// Correct the minimum string length if need be
		if (MINIMUM_STRING_LENGTH < 4) {
			println("The entered minimum string length of " + MINIMUM_STRING_LENGTH
					+ " is lower than four, and has thus been adjust to four");
			MINIMUM_STRING_LENGTH = 4;
		}

		// Get all strings from the currently open program
		List<String> stringsFromCurrentProgram = getStringsFromCurrentProgram(MINIMUM_STRING_LENGTH);

		// Parse the JSON file into a Java object
		Map<String, MalpediaFlossedString> flossed = requestAndParse(stringsFromCurrentProgram);

		// Create and print the message about the non-occurring strings
		println("Strings not occurring in the Malpedia string set (this check is case sensitive):");

		/*
		 * Get a list of strings from the flossed object, since the keys are the
		 * strings. To easily iterate over the strings and to be able to fetch results,
		 * an ArrayList is used, rather than the set.
		 */
		List<String> stringKeys = new ArrayList<>(flossed.keySet());

		/*
		 * If no matches are found, an additional message is to be printed for the
		 * analyst. This boolean defines if said message will be printed.
		 */
		boolean noMatches = true;

		// Iterate over all strings within the current program
		for (int i = 0; i < stringsFromCurrentProgram.size(); i++) {
			// Get the current string
			String currentString = stringsFromCurrentProgram.get(i);
			// If the list of flossed strings does not contain the current string
			if (stringKeys.contains(currentString) == false) {
				/*
				 * If no matches are found, set the boolean, which is used to inform the analyst
				 * later on
				 */
				noMatches = false;
				// Printed for the analyst to see
				println(currentString);
			}
		}

		// If no missing strings were found, print a message related to that
		if (noMatches) {
			println("All strings of this binary occur within the Malpedia string set!");
		}
	}

	/**
	 * Send the HTTP POST request to the web service
	 * 
	 * @param body the body of comma separated strings to check
	 * @return the JSON response from the server
	 * @throws IOException
	 */
	private String postRequest(String body) throws IOException {
		URL url = new URL(WEB_API_URL);
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.setRequestMethod("POST");
		connection.setRequestProperty("Content-Type", "application/json");
		connection.setRequestProperty("Accept", "application/json");
		connection.setDoOutput(true);

		try (OutputStream outputStream = connection.getOutputStream()) {
			byte[] rawBody = body.getBytes("utf-8");
			outputStream.write(rawBody, 0, rawBody.length);
		}

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
	 * Creates a comma separated string of the given list
	 * 
	 * @param input the list to convert
	 * @return the converted list, in string format, where each string is
	 *         encapsulated between quotes
	 */
	private String csvFormatList(List<String> input) {
		String output = "";

		for (String string : input) {
			output += encapsulate(string) + ",";
		}
		return output.substring(0, output.length() - 1);
	}

	/**
	 * Encapsulates the given string between quotes
	 * 
	 * @param input the string to encapsulate
	 * @return the encapsulated string
	 */
	private String encapsulate(String input) {
		return "\"" + input + "\"";
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
					if (isFullyHumanReadable(s)) {
						// Add the string to the set
						strings.add(s);
					} else {
						println(s);
					}
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
	 * Non human readable characters will throw an error from the web server
	 * 
	 * @param input the string to check
	 * @return true if the string is fully readable, false if not
	 */
	private boolean isFullyHumanReadable(String input) {
		// Get the byte representation from the given string
		byte[] bytes = input.getBytes();

		// Iterate over all bytes
		for (byte b : bytes) {
			// Values lower than 0x20 are not human readable
			if (b < 0x20) {
				/*
				 * 0x09 is a horizontal tab
				 * 
				 * 0x0A is a line feed
				 * 
				 * 0x0D is carriage feed
				 */
				if (b != 0x09 && b != 0x0A && b != 0x0D) {
					return false;
				}
			}
			// 0xFF is an unreadable character
			if (b == 0xFF) {
				return false;
			}
		}
		return true;
	}

	/**
	 * A parsing function, which contains a custom GSON parser to properly parse the
	 * Malpedia JSON set
	 * 
	 * @param jsonFile the Malpedia JSON file, as a Java File object
	 * @return the custom Java object with all results
	 * @throws IOException
	 */
	private Map<String, MalpediaFlossedString> requestAndParse(List<String> stringsFromCurrentProgram)
			throws IOException {
		/*
		 * Create a custom JSON deserializer
		 */
		JsonDeserializer<MalpediaFlossed> deserializer = new JsonDeserializer<MalpediaFlossed>() {
			@Override
			public MalpediaFlossed deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
					throws JsonParseException {
				JsonObject jsonObject = json.getAsJsonObject();

				if (jsonObject.get("status").getAsString().equalsIgnoreCase("successful") == false) {
					printerr("Unssucessful request!");
					return null;
				}

				Map<String, MalpediaFlossedString> stringMapping = new HashMap<>();

				JsonArray data = jsonObject.get("data").getAsJsonArray();
				for (int count = 0; count < data.size(); count++) {
					JsonObject entry = data.get(count).getAsJsonObject();

					String string = entry.get("string").getAsString();

					boolean matched = entry.get("matched").getAsBoolean();

					List<String> encodings = new ArrayList<>();
					JsonElement element = entry.get("encodings");
					if (element != null) {
						JsonArray encodingsJson = element.getAsJsonArray();
						for (int i = 0; i < encodingsJson.size(); i++) {
							String encoding = encodingsJson.get(i).getAsString();
							encodings.add(encoding);
						}
					}

					List<String> tags = new ArrayList<>();
					element = entry.get("tags");
					if (element != null) {
						JsonArray tagsJson = element.getAsJsonArray();
						for (int i = 0; i < tagsJson.size(); i++) {
							String tag = tagsJson.get(i).getAsString();
							tags.add(tag);
						}
					}

					List<String> families = new ArrayList<>();

					element = entry.get("families");
					if (element != null) {
						JsonArray familiesJson = element.getAsJsonArray();
						for (int i = 0; i < familiesJson.size(); i++) {
							String family = familiesJson.get(i).getAsString();
							families.add(family);
						}
					}

					Integer familyCount = -1;
					element = entry.get("family_count");
					if (element != null) {
						familyCount = element.getAsInt();
					}

					List<String> methods = new ArrayList<>();
					element = entry.get("methods");
					if (element != null) {
						JsonArray methodsJson = element.getAsJsonArray();
						for (int i = 0; i < methodsJson.size(); i++) {
							String method = methodsJson.get(i).getAsString();
							methods.add(method);
						}
					}

					MalpediaFlossedString stringEntry = new MalpediaFlossedString(matched, encodings, families,
							familyCount, methods, tags);
					stringMapping.put(string, stringEntry);
				}

				return new MalpediaFlossed(stringMapping);
			}
		};

		// Create the request body
		String body = csvFormatList(stringsFromCurrentProgram);

		// Store the JSON response from the server
		String json = postRequest(body);

		// Initialise the GSON builder
		GsonBuilder gsonBuilder = new GsonBuilder();

		// Register the custom deserializer
		gsonBuilder.registerTypeAdapter(MalpediaFlossed.class, deserializer);

		// Create a Gson instance, with the custom adapter type
		Gson customGson = gsonBuilder.create();

		/*
		 * Parse the JSON into a Java object, and return the mapping from the wrapper
		 * object
		 */
		return customGson.fromJson(json, MalpediaFlossed.class).getData();
	}

	private class MalpediaFlossed {
		private Map<String, MalpediaFlossedString> data;

		public MalpediaFlossed(Map<String, MalpediaFlossedString> data) {
			super();
			this.data = data;
		}

		public Map<String, MalpediaFlossedString> getData() {
			return data;
		}
	}

	private class MalpediaFlossedString {
		boolean matched;
		private List<String> encodings;
		private List<String> families;
		private Integer familyCount;
		private List<String> methods;
		private List<String> tags;

		public MalpediaFlossedString() {

		}

		public MalpediaFlossedString(boolean matched, List<String> encodings, List<String> families,
				Integer familyCount, List<String> methods, List<String> tags) {
			super();
			this.matched = matched;
			this.encodings = encodings;
			this.families = families;
			this.familyCount = familyCount;
			this.methods = methods;
			this.tags = tags;
		}

		public boolean isMatched() {
			return matched;
		}

		public List<String> getEncodings() {
			return encodings;
		}

		public List<String> getFamilies() {
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
}