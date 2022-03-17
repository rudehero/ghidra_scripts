from ghidra.app.emulator import EmulatorHelper
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import ghidra.program.model.data
import ghidra.pcode.emulate.EmulateExecutionState
import re
#TODO -- Finalize emulation code; update to support 32 or 64 based on addr_size
#cleanup all teh address factory calls

emulateIt = False
scriptArgs = getScriptArgs()
if("emulate" in scriptArgs):
	emulateIt = True

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

addr_size = currentProgram.getMetadata()['Address Size']
width = int(addr_size) // 8
addrFactory = currentProgram.getAddressFactory()
fm = currentProgram.getFunctionManager()
funcs = fm.getExternalFunctions()


def traceUniqueArg(arg, lsm, count=0):
        out = ""
        if(count > 10):
            print(arg)
            print("over 10 deep")
            return "Hit recursive limit"
        argdef = arg.getDef()
        if not argdef:
            return out
        argin = argdef.getInputs()
        if not argin:
            return out
        out += "\t\t{}{}\n".format("\t" * count, argdef)
        for a in argin:
            if(a.isUnique()):
                out += traceUniqueArg(a,lsm,(count + 1))
            elif(a.isConstant()):
                out += "\t\t{}const {}\n".format("\t" * (count + 1), a.getOffset())
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
                if(highArgSym in lsm.getSymbols()):
                    if(highArgSym.isParameter()):
                        out += "\t\t{}Is parameter to calling function\n".format("\t" * (count + 1))
        return out

# Step 1. Get functions that call the target function ('callers')
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
#emuMonitor = ConsoleTaskMonitor()
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
        #retrieve the C code syntax for later searching
        code = res.getDecompiledFunction().getC()
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
                        hArgNames = []
                        for arg in args:
                            highArg = arg.getHigh()
                            out += "\tArg {}:\t{} {}\n".format(args.index(arg), highArg.getDataType(), highArg.getName())

                            highArgSym = highArg.getSymbol()
                            if(highArgSym in lsm.getSymbols()):
                                if(highArgSym.isParameter()):
                                    out += "\t\tIs parameter to calling function\n"
                            #if(arg.isUnique()):
                                else:
                                    out += "{}".format(traceUniqueArg(arg,lsm))
                            else:
                                out += "{}".format(traceUniqueArg(arg,lsm))

                            if(highArg.getName() != "UNNAMED"):
                                hArgNames.append(highArg.getName())
                        #super noisy...not sure how much it actually helps.
                        #when there's not a lot of output and not a lot of duplication it's pretty good
                        #prints all occurences of the argument in hte function
                        #searchString = r".*?{}.*?\n".format(symbol.getName())
                        #prints all occurences of the function in question with the parameter in question
                        searchNames = ''.join("%s.*?" % h for h in hArgNames)
                        searchString = r".*?{}.*?{}\n".format(fkey, searchNames)
                        matches = re.findall(searchString, code)
                        out += "\tPossible C Code of this call:\n"
                        for m in matches:
                            out += "\t\t{}".format(m.lstrip())
                            #out += "\t\t{} \n".format(symbol.getName()))
                            #out += "\t\tType: {}\n".format(symbol.dataType))
                            #out += "\t\tSize: {}\n".format(symbol.size))
                            #out += "\t\tStor: {}\n".format(symbol.storage))
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
                                '''
                                emuStatus = emuHelper.getExecutionState()
#ghidra.pcode.emulate.EmulateExecutionState
                                #check status of the emulator
                                #might actually be more than I need
                                if(emuStatus == ghidra.pcode.emulate.EmulateExecutionState.BREAKPOINT):
                                    #check address of breakpoint
                                    if(currExecAddr == op.getSeqnum().getTarget()):
                                        print("At the call!")
                                        out += "Emulator derived param values\n"
                                        out += "\tArg1: {}\tArg2: {}\tArg3: {}".format(emuHelper.readRegister("RDI"), emuHelper.readRegister("RSI"), emuHelper.readRegister("RDX"))
                                        


                                elif(emuStatus == ghidra.pcode.emulate.EmulateExecutionState.FAULT):
                                    #check fault and take action
                                elif(emuStatus == ghidra.pcode.emulate.EmulateExecutionState.STOPPED):
                                    #honestly not sure what to do here...
                            '''
                            #end emulation, clear out emuhelper
                            emuHelper.dispose()



                            



                        out += "\n----------------------------------\n"

if("Found" in out):
    f = open(currentProgram.getName() + ".dangFuncs.txt", 'w')
    f.write(out)
    f.close()
