from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

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
f = open(currentProgram.getName() + ".dangFuncs.txt", 'w')
f.write("-------------------------------------------------------\n")
for func in funcs:
    #if func.getName() == TARGET_FUNC:
    if func.getName() in TARGET_FUNCS:
        calls = []
        f.write("\nFound {} @ 0x{}\n".format(func.getName(), func.getEntryPoint()))
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

f.write("-------------------------------------------------------\n")
fkeys = fnames.keys()
fkeys.sort()
for fkey in fkeys:
    f.write("-------------------------------------------------------\n")
    f.write("{}\n".format(fkey.center(54)))
    f.write("-------------------------------------------------------\n")
    calls = fnames[fkey]
    for call in calls:
        local_variables = call[0].getAllVariables()
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
                        f.write("Call to {} at {} in {} has {} argument/s:\n\t{}\n".format(fkey, op.getSeqnum().getTarget(), call[0].getName(), len(args), [x for x in args]))
                        for arg in args:
                            vndef = arg.getDef()
                            if vndef:
                                vndef_inputs = vndef.getInputs()
                                for defop_input in vndef_inputs:
                                    defop_input_offset = defop_input.getAddress().getOffset() & bitmask
                                    for lv in local_variables:
                                        unsigned_lv_offset = lv.getMinAddress().getUnsignedOffset() & bitmask
                                        if unsigned_lv_offset == defop_input_offset:
                                            f.write("\tArg {} {} : {}\n".format(args.index(arg), arg, lv))
                # If             we get here, varnode is likely a "acStack##" variable.
                                for vndef_input in vndef_inputs:
                                    defop_input_offset = vndef_input.getAddress().getOffset() & bitmask
                                    for symbol in lsm.getSymbols():
                                        if symbol.isParameter(): 
                                            pass
                                        if defop_input_offset == symbol.getStorage().getFirstVarnode().getOffset() & bitmask:
                                            pass
                        f.write("\n")
f.close()
