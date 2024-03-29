from ghidra.app.emulator import EmulatorHelper
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import ghidra.program.model.data
import ghidra.pcode.emulate.EmulateExecutionState
import re
#in the event xrefs are printed but no calls are printed:
#possibly a jump/call table in use, indirect calling preventing ghidra from
#finding a specific static op calling to the function
#at this point you just have to go into ghidra proper to investigate further if warranted

#TODO -- Finalize emulation code; update to support 32 or 64 based on addr_size
#cleanup all teh address factory calls
#make it work for non x86?
#acknowledgement to https://github.com/HackOvert/GhidraSnippets
#which was incredibly useful when first starting out working with the Ghidra
#python API
#the snippet "Analyzing function arguments at cross references" served as a starting point
#for the driver portion of this script


scriptArgs = getScriptArgs()

TARGET_FUNCS = []
for arg in scriptArgs:
    TARGET_FUNCS.append(arg)



addrSize = int(currentProgram.getMetadata()['Address Size'])
width = addrSize // 8
if addrSize == 32:
    stackPointer = "ESP"
elif addrSize == 64:
    stackPointer = "RSP"
else:
    stackPointer = "undefined"
addrFactory = currentProgram.getAddressFactory()
fm = currentProgram.getFunctionManager()
#pulls back external and internal functions, but not the external stubs
#NOTE TO SELF: might be worth changing dangerousfuns to utilize this
funcs = fm.getFunctionsNoStubs(True)


#trace back the source of unique arguments
#also just keep tracing arguments back to their eventual source
#called after first look at args, and then calls itself as well
def traceUniqueArg(arg, lsm, count=0):
        out = ""
        if(count > 10):
            return "\t\tHit recursion limit\n".format("\t" * (count + 1))
        argdef = arg.getDef()
        if not argdef:
            return out
        argin = argdef.getInputs()
        if not argin:
            return out
        out += "\t\t{}{}\n".format("\t" * count, argdef)
        if(argdef.getMnemonic() == "PTRSUB"):
            if(str(currentProgram.getRegister(argin[0])) == stackPointer):
                if(argin[1].isConstant()):
                    for s in lsm.getSymbols():
                        if(argin[1].getOffset() == s.getStorage().getFirstVarnode().getOffset()):
                            out += "\t\t{}{}:{}\n".format("\t" * (count + 1), s.getName(), s.getStorage())
                            return out
        for a in argin:
            if(a.isUnique()):
                out += traceUniqueArg(a,lsm,(count + 1))
            elif(a.isConstant()):
                out += "\t\t{}const {}\n".format("\t" * (count + 1), hex(a.getOffset())[0:-1])
            elif(a.isAddress() and argdef.getMnemonic() == "CALL"):
                out += "\t\t{}{}\n".format("\t" * (count + 1), fm.getFunctionAt(a.getAddress()))
            else:
                highArg = a.getHigh()
                if not highArg:
                    continue
                out += "\t\t{}{} {}\n".format("\t" * (count + 1), highArg.getDataType(), highArg.getName())
                if(highArg.getName() == "UNNAMED"):
                    out += traceUniqueArg(a,lsm,(count + 1))
                highArgSym = highArg.getSymbol()
                if(highArgSym):
                    if("Stack" in str(highArgSym.getStorage())):
                        out += "\t\t{}{}\n".format("\t" * (count + 1), highArgSym.getStorage())
                if(highArgSym in lsm.getSymbols()):
                    if(highArgSym.isParameter()):
                        out += "\t\t{}Is parameter to calling function\n".format("\t" * (count + 1))
        return out

#main driving code
#find the functions of interest and get all xrefs to the functions
#since i'm looking for library calls need to find the thunk address
#for each xref creates a tuple with the function containing the call
#  and the address called to
#all of the xref tuples are put into a list, and deduplicated
#then a dictionary is created tieing hte lists to the function name of interest
target_addr = 0
fnames = dict()
for func in funcs:
    if func.getName() in TARGET_FUNCS:
        calls = []
        refs = getReferencesTo(func.getEntryPoint())
        xrefs = []
        for ref in refs:
            if ref.referenceType.isData():
                pass
            else:
                xrefs.append((ref.getFromAddress(), ref.getToAddress(), ref.getReferenceType()))
        xrefList = []
        for xref in xrefs:
                caller = getFunctionContaining(xref[0])
                xrefList.append((caller, xref[1], xref[0], xref[2]))
                if not (caller in [c[0] for c in calls]):
                    calls.append((caller, xref[1], xref[0], xref[2]))
        calls = list(set(calls))
        fnames[func.getName()] = (calls, xrefList)

#set up decompiliation interface, iterate through all of the calls of interest
#and decompile each call that was previously found
#retrieves C code for each iteration to search for the actual call in C based
#on wildcards as identified argument names
#as such it may not find the actual call in C code or it might find multiple potential
#matches which require user analysis to determine
monitor = ConsoleTaskMonitor()
decompOptions = DecompileOptions()
decompIface = DecompInterface()
decompIface.setOptions(decompOptions)
decompIface.openProgram(currentProgram)

fkeys = fnames.keys()
fkeys.sort()
for fkey in fkeys:
    out = ""
    out += "-------------------------------------------------------\n"
    out += "-------------------------------------------------------\n"
    out += "{}\n".format(fkey.center(54))
    out += "-------------------------------------------------------\n"
    calls = fnames[fkey][0]
    out += "XREF List\n".format(fkey.center(54))
    
    for x in fnames[fkey][1]:
        out += "{} to {} from {} reportedly in function {}\n".format(x[3], x[1], x[2], x[0])
    out += "-------------------------------------------------------\n"
    
    for call in calls:
        if(not call):
            continue
        elif(isinstance(call[0], None.__class__)):
            continue
        callerVariables = call[0].getAllVariables()
        res = decompIface.decompileFunction(call[0], 60, monitor)
        #retrieve the C code syntax for later searching
        code = res.getDecompiledFunction().getC()
        high_func = res.getHighFunction()
        lsm = high_func.getLocalSymbolMap()
        symbols = lsm.getSymbols()
        if high_func:
            #get all pcode for the function, iterate until reaching the 
            #stored call
            opiter = high_func.getPcodeOps()
            while opiter.hasNext():
                op = opiter.next()
                mnemonic = str(op.getMnemonic())
                if mnemonic == "CBRANCH":
                    inputs = op.getInputs()
                    addr = inputs[0].getAddress()
                    if addr == call[1]:
                        out += "Jump to {} at {} in {}\n".format(fkey, op.getSeqnum().getTarget(), call[0].getName())
                elif mnemonic == "CALLIND":
                    inputs = op.getInputs()
                    addr = inputs[0].getAddress()
                    if addr == call[1]:
                        out += "Jump to {} at {} in {}\n".format(fkey, op.getSeqnum().getTarget(), call[0].getName())
                #this one likely needs work but i haven't had an example of it come up yet
                elif mnemonic == "BRANCHIND":
                    inputs = op.getInputs()
                    addr = inputs[0].getAddress()
                    if addr == call[1]:
                        out += "Jump to {} at {} in {}\n".format(fkey, op.getSeqnum().getTarget(), call[0].getName())
                elif mnemonic == "BRANCH":
                    inputs = op.getInputs()
                    addr = inputs[0].getAddress()
                    if addr == call[1]:
                        out += "Jump to {} at {} in {}\n".format(fkey, op.getSeqnum().getTarget(), call[0].getName())
                elif mnemonic == "CALLIND":
                    inputs = op.getInputs()
                    addr = inputs[0].getAddress()
                    if addr == call[1]:
                        out += "Indirect Call to {} at {} in {}\n".format(fkey, op.getSeqnum().getTarget(), call[0].getName())
                elif mnemonic == "CALL":
                    inputs = op.getInputs()
                    addr = inputs[0].getAddress()
                    args = inputs[1:] 
                    if addr == call[1]:
                        #after finding the call of interest append info for the arguments
                        #then begin iterating through the arguments and appending their info
                        #and tracing them back further if necessary
                        out += "Call to {} at {} in {} has {} argument/s:\n\t{}\n".format(fkey, op.getSeqnum().getTarget(), call[0].getName(), len(args), [x for x in args])
                        hArgNames = []
                        for arg in args:
                            highArg = arg.getHigh()
                            argName = highArg.getName()
                            if(arg.isConstant()):
                                argName = hex(arg.getOffset())[0:-1]
                            if(argName != "UNNAMED"):
                                    hArgNames.append(argName)
                            else:
                                argdef = arg.getDef()
                                if argdef:
                                    argin = argdef.getInputs()
                                    if argin:
                                        if(argdef.getMnemonic() in ["PTRSUB"]):
                                            if(str(currentProgram.getRegister(argin[0])) == stackPointer):
                                                if(argin[1].isConstant()):
                                                    for s in lsm.getSymbols():
                                                        if(argin[1].getOffset() == s.getStorage().getFirstVarnode().getOffset()):
                                                            argName = s.getName()
                                                            hArgNames.append(argName)
                                        elif(argdef.getMnemonic() == "CAST"):
                                            if(argin[0].getHigh()):
                                                argName = argin[0].getHigh().getName()
                                                if(argName != "UNNAMED"):
                                                    hArgNames.append(argName)
                                            

                            out += "\tArg {}:\t{} {}\n".format(args.index(arg), highArg.getDataType(), argName)

                            highArgSym = highArg.getSymbol()
                            if(highArgSym in lsm.getSymbols()):
                                if(highArgSym.isParameter()):
                                    out += "\t\tIs parameter to calling function\n"
                                else:
                                    out += "{}".format(traceUniqueArg(arg,lsm))
                            else:
                                out += "{}".format(traceUniqueArg(arg,lsm))

                        searchNames = ''.join("%s.*?" % h for h in hArgNames)
                        searchString = r".*?{}\(.*?{}\n".format(fkey, searchNames)
                        matches = re.findall(searchString, code)
                        out += "\tPossible C Code of this call:\n"
                        for m in matches:
                            out += "\t\t{}".format(m.lstrip())
                        out += "\n----------------------------------\n"


    #only output a file with contents if one of the calls of interest was actually found
    if("XREF" in out):
        f = open(currentProgram.getName() + "." + fkey + ".funcUsage.txt", 'w')
        f.write("Binary name: {}\n".format(currentProgram.getName()))
        f.write("Location in Ghidra Project: {}\n".format(currentProgram.getDomainFile()))
        f.write("Location on disk: {}\n".format(currentProgram.getExecutablePath()))
        f.write(out)
        f.close()
