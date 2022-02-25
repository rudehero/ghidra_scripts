from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

TARGET_FUNC = "memcpy"
TARGET_FUNCS = [
            "strcpy",
            "strncpy",
            "strlen"
            ]

bitness_masks = {
        '16': 0xffff,
        '32': 0xffffffff,
        '64': 0xffffffffffffffff,
    }

try:
      addr_size = currentProgram.getMetadata()['Address Size']
      bitmask = bitness_masks[addr_size]
except KeyError:
      raise Exception("Unsupported bitness: {}. Add a bit mask for this target.".format(addr_size))

# Step 1. Get functions that call the target function ('callers')
fm = currentProgram.getFunctionManager()
funcs = fm.getExternalFunctions()
target_addr = 0
fnames = dict()
out = ""
out + = currentProgram.getName() + ".strCpyNoStrLen.txt", 'w')

out += "-------------------------------------------------------\n"
for func in funcs:
    #if func.getName() == TARGET_FUNC:
    if func.getName() in TARGET_FUNCS:
        calls = []
        out += "Found {} @ 0x{}\n".format(func.getName(), func.getEntryPoint())
        thunks = func.getFunctionThunkAddresses()
        thunk = thunks[0]
        refs = getReferencesTo(thunk)
        xrefs = []
        for ref in refs:
            if ref.referenceType.isData():
                pass
            else:
                for r in getReferencesTo(ref.fromAddress):
                    xrefs.append((r.fromAddress, r.toAddress))
        for xref in xrefs:
                if getFunctionContaining(xref[0]) in fnames:
                    if (func.getName(), xref[1]) not in fnames[getFunctionContaining(xref[0])]:
                        fnames[getFunctionContaining(xref[0])].append((func.getName(), xref[1]))
                else:
                    fnames[getFunctionContaining(xref[0])] = [(func.getName(), xref[1])]

# Step 2. Decompile all callers and find PCODE CALL operations leading to `target_add`
options = DecompileOptions()
monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.setOptions(options)
ifc.openProgram(currentProgram)

out += "-------------------------------------------------------\n"
fkeys = fnames.keys()
fkeys.sort()
#get the calls within each function in ascending order
#may not be 100% accurate for execution order based on function logic
#but is at least cleaner

for fkey in fkeys:
    out += "-------------------------------------------------------\n"
    out += "{}\n".format(fkey.getName().center(54))
    out += "-------------------------------------------------------\n"
    calls = fnames[fkey]
    strcpy_exists = 0 
    strlen_exists = 0
    for call in calls:
        if call[0] == "strlen":
            strlen_exists = 1
        elif call[0] == "strcpy":
            strcpy_exists = 1

    if(strcpy_exists == 1 and not strlen_exists == 1):
        out += "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        out += "!!!STRCPY EXISTS IN FUNCTION WITHOUT ANY STRLEN CALLS!!!\n"
        out += "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"

    for call in calls:
        callerVariables = fkey.getAllVariables()
        res = ifc.decompileFunction(fkey, 60, monitor)
        high_func = res.getHighFunction()
        lsm = high_func.getLocalSymbolMap()
        symbols = lsm.getSymbols()
        if high_func:
            opiter = high_func.getPcodeOps()
            while opiter.hasNext():
                op = opiter.next()
                mnemonic = str(op.getMnemonic())
                if mnemonic == "CALL":
                    inputs = op.getInputs()
                    addr = inputs[0].getAddress()
                    args = inputs[1:] # List of VarnodeAST types
                    if addr == call[1]:
                        out += "Call in {} at {} to {} has {} argument/s:\n\t{}\n".format(fkey, op.getSeqnum().getTarget(), call[0], len(args), [x for x in args])
                        for arg in args:
                            out += "\tArg {}:\n".format(args.index(arg))
                            vndef = arg.getDef()
                            if vndef:
                                vndef_inputs = vndef.getInputs()
                                for defop_input in vndef_inputs:
                                    defop_input_offset = defop_input.getAddress().getOffset() & bitmask
                                    for cv in callerVariables:
                                        unsigned_cv_offset = cv.getMinAddress().getUnsignedOffset() & bitmask
                                        if unsigned_cv_offset == defop_input_offset:
                                            out += "\t\t{}\n".format(cv)
                                    for symbol in lsm.getSymbols():
                                        if defop_input_offset == symbol.getStorage().getLastVarnode().getOffset() & bitmask:
                                            #f.write("\t\t{} \n".format(symbol.getName()))
                                            #f.write("\t\tType: {}\n".format(symbol.dataType))
                                            #f.write("\t\tSize: {}\n".format(symbol.size))
                                            #f.write("\t\tStor: {}\n".format(symbol.storage))
                                            if(symbol.isParameter()):
                                                out += "\t\tIs calling func parameter\n".format(args.index(arg))
                        out += "\n"
if( "strcpy" in out):
    f = open(currentProgram.getName() + ".strCpyNoStrLen.txt", 'w')
    f.write(out)
    f.close()

