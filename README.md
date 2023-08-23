# GhidraScripts
Scripts to run within Ghidra, maintained by the Trellix ARC team.

## How to use Ghidra scripts
When Ghidra’s CodeBrowser is open, the green play button in the icon row opens the Script Manager, as can be seen in the screenshot below. Alternatively, one can open the Window tool strip menu item, and select Script Manager.

![The green play button opens the Script Manager](images/displayScriptManager.png)

Once open, one can manage the script directories with the hamburger menu in the top right corner of the Script Manager.

![The script manager, and the Manage Script Directories hamburger button](images/scriptManager.png)

Within that menu, one can click on the green plus to add a folder to the list of locations where scripts are fetched from. Once added, press the two green arrows to refresh the list.

![The bundle manager to add and/or remove folders from the places where Ghidra scripts are loaded from](images/bundleManager.png)

Once the refresh action has completed, the script should be in the list, and can be searched for using the textbox next to the filter label. To execute a script, simply double click it, or press the green play button within the Script Manager.

### Golang related scripts
Simply run the scripts and observe the output in the Console Log. Error messages are indicative of what went wrong (i.e. a non supported file format, or an issue finding a specific data structure). Non-error messages are indicative of what the script has changed and updated.

### Sharem.java
Configure [SHAREM](https://github.com/Bw3ll/sharem/) to run [headless](https://github.com/Bw3ll/sharem/wiki/2.-Quick-Start-Analysis#configuration-file), and edit the script to contain the correct path to both Python and SHAREM's main Python file. Additionally, ensure the correct parameter for the shellcode's bitness is used, along with the correct path to the shellcode sample. Once all is configured, simply run the Ghidra script and wait until SHAREM finishes its execution. There is no progress bar for SHAREM's execution. Once it is done, the code will load the JSON file and start annotating the given offsets in Ghidra, which will be visible in the Console Log.

## Questions and/or feedback
Please open an issue in this repository with any questions and/or feedback you have, as long as it is related to the scripts within the repository.
