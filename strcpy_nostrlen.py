from ghidra.app.emulator import EmulatorHelper
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import ghidra.program.model.data
import ghidra.pcode.emulate.EmulateExecutionState
import re
#TODO -- Finalize emulation code; update to support 32 or 64 based on addr_size
#cleanup all teh address factory calls
#make it work for non x86?
#acknowledgement to https://github.com/HackOvert/GhidraSnippets
#which was incredibly useful when first starting out working with the Ghidra
#python API
#the snippet "Analyzing function arguments at cross references" served as a starting point
#for this script

emulateIt = False
scriptArgs = getScriptArgs()
if("emulate" in scriptArgs):
    emulateIt = True

TARGET_FUNCS = [
            "strcpy",
            "strlen",
            "strncpy"
            ]

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
funcs = fm.getExternalFunctions()


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
                    #for s in lsm.getSymbols():
                    #    if(a.getOffset() == s.getStorage().getFirstVarnode().getOffset()):
                    #        out += "\t\t{}{}\n".format("\t" * (count + 1), s.getName())
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
#since the thunk is what will actually be xref'd
#for each xref creates a tuple with the function containing the call
#  and the address called to
#all of the xref tuples are put into a list
#modified version of potentialDangerous.  Store in dictionary of calling function
target_addr = 0
fnames = dict()
out = ""
out += "-------------------------------------------------------\n"
for func in funcs:
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
                if getFunctionContaining(xref[0]) in fnames:
                    if (func.getName(), xref[1]) not in fnames[getFunctionContaining(xref[0])]:
                        fnames[getFunctionContaining(xref[0])].append((func.getName(), xref[1]))
                else:
                    fnames[getFunctionContaining(xref[0])] = [(func.getName(), xref[1])]

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

out += "-------------------------------------------------------\n"
fkeys = fnames.keys()
fkeys.sort()
for fkey in fkeys:
    if(isinstance(fkey, None.__class__)):
        continue
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
        if(not call):
            continue
        callerVariables = fkey.getAllVariables()
        res = decompIface.decompileFunction(fkey, 60, monitor)
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
                if mnemonic == "CALL":
                    inputs = op.getInputs()
                    addr = inputs[0].getAddress()
                    args = inputs[1:] 
                    if addr == call[1]:
                        #after finding the call of interest append info for the arguments
                        #then begin iterating through the arguments and appending their info
                        #and tracing them back further if necessary
                        out += "Call in {} at {} to {} has {} argument/s:\n\t{}\n".format(fkey, op.getSeqnum().getTarget(), call[0], len(args), [x for x in args])
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
                        searchString = r".*?{}\(.*?{}\n".format(call[0], searchNames)
                        matches = re.findall(searchString, code)
                        out += "\tPossible C Code of this call:\n"
                        for m in matches:
                            out += "\t\t{}".format(m.lstrip())
                        #instantiate eumlator helper to try and track values
                        if emulateIt:
                            emuHelper = EmulatorHelper(currentProgram)
                            #create a patterned buffer of data to use when pointers are in play
                            #using a pre-created pattern file to save on execution time.  generated via:
                            #/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 10000
                            with open("/home/rudehero/gits/ghidra_scripts/patternfile_10000", "rb") as f:
                                pattern = f.read()
                            #general int for when necessary
                            num = 0x41
                            #writing pattern to "random" address that hopefully won't clobber
                            memAddr = currentProgram.getAddressFactory().getAddress("0xF000")
                            emuHelper.writeMemory(memAddr, pattern)

                            #create fake start conditions  to allow exeecution
                            #caller fun = call[0], callee addr = op.getSeqnum().getTarget()
                            #set end breakpoint at the call of interest
                            emuHelper.setBreakpoint(op.getSeqnum().getTarget())
                            #fake return address to check in case we short circuit out
                            bogusReturn = int("0x{}".format(addrFactory.getAddress("0")), 16)
                            #pull addr for callee func and ensure int format
                            calleeAddr = int("0x{}".format(call[0].getEntryPoint()), 16)
                            emuHelper.writeRegister(emuHelper.getPCRegister(), calleeAddr)
                            #set RBP and RSP values
                            stackAddr = int("0x{}".format(currentProgram.getAddressFactory().getDefaultAddressSpace().getMaxAddress()), 16) - 0x7FFF
                            emuHelper.writeRegister("RSP", stackAddr)
                            stackOffset = 0
                            emuHelper.writeStackValue(stackOffset, width, bogusReturn)
                            stackOffset += width
                            
                            #figure out params needed to supply...
                            numParams = call[0].getParameterCount()
                            params = call[0].getParameters()
                            for p in params:
                                if(isinstance(p.getDataType(), ghidra.program.model.data.Pointer)):
                                    if(p.getVariableStorage().isRegisterStorage()):
                                        emuHelper.writeRegister(p.getVariableStorage().getRegister(), int("0x{}".format(memAddr), 16))
                                    else:
                                        #should be passed on stack
                                        emuHelper.writeStackMemory(stackOffset, width, int("0x{}".format(memAddr), 16))
                                        stackOffset += width
                                else:
                                    if(p.getVariableStorage().isRegisterStorage()):
                                        emuHelper.writeRegister(p.getVariableStorage().getRegister(), num)
                                    else: 
                                        emuHelper.writeStackMemory(stackOffset, width, num)
                                        stackOffset += width

                            #main emulation driver
                            #while emuMonitor.isCancelled() == False:
                            print("starting emulation run")
                            while monitor.isCancelled() == False:
                                succ = emuHelper.run(monitor)
                                if(succ == False):
                                    print("Emulation error: {}.  Aborting".format(emuHelper.getLastError()))
                                    #print("Top stack mem: {}".format(emuHelper.readStackValue(0, 8, False)))
                                    break
                                currExecAddr = emuHelper.getExecutionAddress()
                                if (currExecAddr == bogusReturn):
                                    print("Emulation short circuited out of function.")
                                    break
                                if(currExecAddr == op.getSeqnum().getTarget()):
                                    print("At the call!")
                                    out += "Emulator derived param values\n"
                                    out += "\tArg1: {}\tArg2: {}\tArg3: {}".format(emuHelper.readRegister("RDI"), emuHelper.readRegister("RSI"), emuHelper.readRegister("RDX"))
                                    break
                            #end emulation, clear out emuhelper
                            emuHelper.dispose()
                            
                        out += "\n----------------------------------\n"

#only output a file with contents if one of the calls of interest was actually found
if("strcpy" in out):
    if ("EXISTS" in out):
        f = open(currentProgram.getName() + ".strCpyNoStrLen.txt", 'w')
    else:
        f = open(currentProgram.getName() + ".strCpy.txt", 'w')
	f.write("Binary name: {}\n".format(currentProgram.getName()))
    f.write("Location in Ghidra Project: {}\n".format(currentProgram.getDomainFile()))
    f.write("Location on disk: {}\n".format(currentProgram.getExecutablePath()))
    f.write(out)
    f.close()
