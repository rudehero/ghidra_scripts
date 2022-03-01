from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import re

TARGET_FUNC = "memcpy"
TARGET_FUNCS = [
#            "strcpy",
            "strcat",
            "sf.writef",
            "vsf.writef",
            "gets",
#            "strlen",
            "scanf",
            "fscanf",
            "sscanf",
            "vscanf",
            "vsscanf",
            "vfscanf",
            "system",
            "exec",
            "memcpy"
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
out += "-------------------------------------------------------\n"
for func in funcs:
    #if func.getName() == TARGET_FUNC:
    if func.getName() in TARGET_FUNCS:
        calls = []
        out += "\nFound {} @ 0x{}\n".format(func.getName(), func.getEntryPoint())
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
                call = getFunctionContaining(xref[0])
                calls.append((call, xref[1]))
        calls = list(set(calls))
        fnames[func.getName()] = calls

# Step 2. Decompile all callers and find PCODE CALL operations leading to `target_add`
options = DecompileOptions()
monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.setOptions(options)
ifc.openProgram(currentProgram)

out += "-------------------------------------------------------\n"
fkeys = fnames.keys()
fkeys.sort()
for fkey in fkeys:
    out += "-------------------------------------------------------\n"
    out += "{}\n".format(fkey.center(54))
    out += "-------------------------------------------------------\n"
    calls = fnames[fkey]
    for call in calls:
        callerVariables = call[0].getAllVariables()
        res = ifc.decompileFunction(call[0], 60, monitor)
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
                        out += "Call to {} at {} in {} has {} argument/s:\n\t{}\n".format(fkey, op.getSeqnum().getTarget(), call[0].getName(), len(args), [x for x in args])
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
                                            if(symbol.isParameter()):
                                                out += "\t\tIs calling func parameter\n"
                                            code = res.getDecompiledFunction().getC()
                                            #super noisy...not sure how much it actually helps.
                                            #when there's not a lot of output and not a lot of duplication it's pretty good
                                            #prints all occurences of the argument in hte function
                                            #searchString = r".*?{}.*?\n".format(symbol.getName())
                                            #prints all occurences of the function in question with the parameter in question
                                            searchString = r".*?{}.*?{}.*?\n".format(fkey, symbol.getName())
                                            matches = re.findall(searchString, code)
                                            for m in matches:
                                                out += "\t\t{}".format(m.lstrip())
                                            #out += "\t\t{} \n".format(symbol.getName()))
                                            #out += "\t\tType: {}\n".format(symbol.dataType))
                                            #out += "\t\tSize: {}\n".format(symbol.size))
                                            #out += "\t\tStor: {}\n".format(symbol.storage))
                        out += "\n----------------------------------\n"

if("Found" in out):
    f = open(currentProgram.getName() + ".dangFuncs.txt", 'w')
    f.write(out)
    f.close()
