# First attempt at script to find potentially dangerous functions
# @category: Functions
import re
import __main__ as ghidra_app
#functions to look for

if __name__ == '__main__':
    dFuncs = 	[
    		"strcpy",
    		"strcat",
    		"sprintf",
    		"vsprintf",
    		"gets",
    		"strlen",
    		"scanf",
    		"fscanf",
    		"sscanf",
    		"vscanf",
    		"vsscanf",
    		"vfscanf",
    		"realpath",
    		"getopt",
    		"getpass",
    		"streadd",
    		"strecpy",
    		"strtrns",
    		"getwd",
    		"system",
    		"exec"
    		]
    
    dFuncStr = '%s' % '|'.join(dFuncs)
    
    # Get info about the current program
    program_name = ghidra_app.currentProgram.getName()
    
    #get the imports
    st = ghidra_app.currentProgram.getSymbolTable()
    im = st.getExternalSymbols()
    
    #check for the funcs defined as dangerous
    found = []
    for i in im:
    	match = re.search(dFuncStr, str(i))
    	if match:
    		found.append(str(i))
    
    if found:
    	print("------------------------------------------------------------")
    	print("{}\nPotentially Dangerous Functions".format(program_name))
    	print("------------------------------------------------------------")
    	for f in found:
    		print(f)

	



