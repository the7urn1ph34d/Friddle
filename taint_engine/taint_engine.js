// Import all instruction handlers
import * as handlers from './handlers/index.js';
// Import utility functions and global state
import { 
    initializeUtils, 
    globalState, 
    colorLog, 
    assert, 
    parseRegOperand, 
    parseMemOperand, 
    iteratorPutCalloutWrapper,
    parseVector,
    taintSIMDRegFromReg,
    taintSIMDRegFromMem,
    taintMemFromSIMDReg,
    checkNZCVFlag
} from './utils.js';

// FIXME: w register cant get value from ctx
// 0x59b4bcbe34: ldrb w8, [x8, x9]
// w8 undefined
// FIXME:
// mem istainted might has a bug. like tainted 4 bytes, but when we use size 5 it still returns true. we need to check this.
// TODO:
// we need to find a way knowing how many instructions we should handle in total, and how many instructions we have handled so far. check source code see how frida define those ins in ctx struct
// TODO: handle shift ins correctly. this includes reg shift in ins.
// TODO: write a function print out all the registers and memory tainted status.
// TODO: write a function print out all the registers and memory status only when they are tainted.
// TODO: for now we have a function only print out the registers and memory status when taint data is changed.
// TODO: consider signed operation, do we need to clear the upper bits or taint them? and how to handle them when we do taint propagation when we check nzcv registers
// TODO: lets log indirect taint. like target is tainted but also the base register is tainted.
// TODO: we might need to handle taint shift in parseRegOperand

// TODO: handle ldr str indirect taint
// TODO: print out taint even when touching taint ptr
// TODO: only print out mem status and ins when touching taint ptr
// TODO: future work: multithreading support. C callback support.
// TODO: we can improve taint_engine performance by checking if operands is touching taint data or not. if not we just skip the taint propagation.


// FIXME: why sometimes we have svc and not handled?

/*
[Pixel 6::My Application ]-> processData at libmyapplication.so 0x715ea16000 0x715eabe2c4
TAINT_START_POS: 0x715eabdfd8
TAINT_STOP_POS: 0x715eabe1e8
Taint started at ins *** 0x715eabdfd8 : sub sp, sp, #0xf0 ***
source -> x0: 0x7fc078b421, x1: 0x4, x2: 0x7fc078b438, x3: 0x7fc078b418
mem tainted: 
0x7fc078b421,0x7fc078b425

regs tainted: 


in parseMemOperand and index is {"type":"mem","value":{"base":"x20","index":"x19","disp":0},"access":"rw"}
[+] 0x747c9b2a74: madd x24, x22, x8, x28 (4 reg reg reg reg) libc.so 0x747c96f000 0x43a74
union in bitmap.js 8 4
[+] 0x747c9be64c: svc #0 (1 imm) libc.so 0x747c96f000 0x4f64c
union in bitmap.js 8 4
instr should be tainted with vectorIndex: 3
{"address":"0x715eb2079c","next":"0x715eb207a0","size":4,"mnemonic":"dup","opStr":"v6.4s, v3.s[3]","operands":[{"type":"reg","value":"v6","vas":"4s","access":"w"},{"type":"reg","value":"v3","vas":"8b","vectorIndex":3,"access":"r"}],"regsAccessed":{"read":["v3"],"written":["v6"]},"regsRead":[],"regsWritten":[],"groups":["neon"]}
*/

import * as arch from "./core/arm64.js";
import {
    Memory as TaintMemory,
    Registers as TaintRegisters,
} from "./core/core.js";

// Stalker.trustThreshold = 0; // default is 1

// var LOG_ENABLED = false;
// // Utility function for logging
// function log(module, str) {
//     if (!LOG_ENABLED) return;
//     console.log(`<${module}: ${str}>`);
// }

///////////////////// functions /////////////////////
// All global state is now managed in utils.js globalState


// bug fix ios
let libdispatchdylib = null;


function init_states() {
    // Initialize all global state in utils
    initializeUtils();

    bug_fix_ios();
    register_stalker_handle();
}

function register_stalker_handle() {
    // TODO: add handle here
    // must show this information before propagation

    // registerStalkerHandle({
    //     onEnter: printInstrDuringRuntime
    // })

    // registerStalkerHandle({
    //     onEnter: showTaintStatusWhenTouchingTaint,
    // })

    ///////////////////// taint propagation /////////////////////
    registerStalkerHandle({
        onEnter: handlers.handleLoadStoreSingleReg,
    });

    registerStalkerHandle({
        onEnter: handlers.handleArithmeticImmediate,
    });

    registerStalkerHandle({
        onEnter: handlers.handleAddressGeneration,
    });

    registerStalkerHandle({
        onEnter: handlers.handleLogicalImmediate,
    });

    registerStalkerHandle({
        onEnter: handlers.handleMoveWideImmediate,
    });

    registerStalkerHandle({
        onEnter: handlers.handleArithmeticShiftedRegister,
    });

    registerStalkerHandle({
        onEnter: handlers.handleLoadStorePair,
    });

    registerStalkerHandle({
        onEnter: handlers.handleLogicalShiftedRegister,
    });

    registerStalkerHandle({
        onEnter: handlers.handleBitOperations,
    });

    registerStalkerHandle({
        onEnter: handlers.handleLoadStoreSingleRegUnscaledOffset,
    });

    // PC relative literal load instruction
    registerStalkerHandle({
        onEnter: handlers.handleLoadSingleRegPcRelativeLiteralLoad,
    });

    registerStalkerHandle({
        onEnter: handlers.handleLoadStoreExclusive,
    });

    registerStalkerHandle({
        onEnter: handlers.handleBitfieldOperations,
    });

    // FIXME: stlxrh only works on onLeave otherwise there will be a deadloop(maybe try newest frida version current is 16.5.6, newest is 16.6.6)
    // we can console.log the taint start and end in callout shows real execution order
    registerStalkerHandle({
        onEnter: handlers.handleLoadAcquireStoreRelease,
    });

    registerStalkerHandle({
        onEnter: handlers.handleMultiply,
    });

    registerStalkerHandle({
        onEnter: handlers.handleDivide,
    });

    registerStalkerHandle({
        onEnter: handlers.handleShiftImmediate,
    });

    // bitfield extract instruction
    registerStalkerHandle({
        onEnter: handlers.handleExtractImmediate,
    });

    // sign/zero extension instruction
    registerStalkerHandle({
        onEnter: handlers.handleSignZeroExtend,
    });

    registerStalkerHandle({
        onEnter: handlers.handleConditionalDataProcessing,
    });

    registerStalkerHandle({
        onEnter: handlers.handleVariableShift,
    });

    registerStalkerHandle({
        onEnter: handlers.handleDataMovement,
    });

    registerStalkerHandle({
        onEnter: handlers.handleFloatingPointSIMDScalarMemoryAccess,
    });

    // floating point register move instruction
    registerStalkerHandle({
        onEnter: handlers.handleFloatingPointMoveRegister,
    });

    // floating point type conversion instruction
    registerStalkerHandle({
        onEnter: handlers.handleFloatingPointConvert,
    });

    // floating point dual source arithmetic instruction
    registerStalkerHandle({
        onEnter: handlers.handleFloatingPointArithmetic2Source,
    });

    registerStalkerHandle({
        onEnter: handlers.handleVectorLoadStoreStructure,
    });

    // vector arithmetic instruction
    registerStalkerHandle({
        onEnter: handlers.handleVectorArithmetic,
    });

    registerStalkerHandle({
        onEnter: handlers.handleVectorTableLookup,
    });

    registerStalkerHandle({
        onEnter: handlers.handleVectorPermute,
    });

    registerStalkerHandle({
        onEnter: handlers.handleCryptoExtension,
    });

    registerStalkerHandle({
        onEnter: handlers.handleVectorShiftImmediate,
    });

    // conditional branch instruction
    registerStalkerHandle({
        onEnter: handlers.handleConditionalBranch,
    });

    // unconditional immediate branch instruction
    registerStalkerHandle({
        onEnter: handlers.handleUnconditionalBranchImm,
    });

    // unconditional register branch instruction
    registerStalkerHandle({
        onEnter: handlers.handleUnconditionalBranchReg,
    });

    // rest instructions are not in any category
    registerStalkerHandle({
        onEnter: handlers.handleOtherInstructions,
    });

    ///////////// after taint operation /////////////// below is for debug purpose
    // there is no onLeave for branch ins.



    // registerStalkerHandle({
    //     onEnter: showRegMemStatus,
    //     onLeave: showRegMemStatus
    // })

    // registerStalkerHandle({
    //     onLeave: showTaintStatusWhenUpdate,
    //     // onLeave: checkIfOpTaintData
    // })

    // registerStalkerHandle({
    //     onEnter: debugOnSpecificIns,
    // });

    // registerStalkerHandle({
    //     onEnter: checkIfStalkerUnfollow,
    // });
    
    // registerStalkerHandle({
    //     onEnter: customHandleOnInstruction,
    // });


    // registerStalkerHandle({
    //     onEnter: printRunningInstruction,
    // });
}


export function init_taint(source, sink) {
    Stalker.unfollow();
    init_states();

    globalState.TAINT_START_POS = source;
    globalState.TAINT_STOP_POS = sink;
    colorLog("TAINT_START_POS: " + globalState.TAINT_START_POS, "blue");
    colorLog("TAINT_STOP_POS: " + globalState.TAINT_STOP_POS, "blue");
}

export function stalker_unfollow_at_addr(addr) {
    globalState.stalker_unfollow_addr = addr;
}

// because of aslr, most of time we dont know addr. most of time we use name and offset to find the addr.
export function stop_taint() {
    Stalker.unfollow();
}

function isBranchIns(instr) {
    const branch_ins_type = ["jump", "call", "return"];
    if (instr.groups)
        return branch_ins_type.some((item) => instr.groups.includes(item));
    return false;
}

function isSomeInsIdontCare(instr) {
    // TODO: be sure that we really dont care about these ins
    return ["nop", "mrs", "cmp", "ccmp", "cmn", "tst", "paciasp", "autiasp"].includes(instr.mnemonic);
    return false
}

function isPrintDebugInfo(instr, instrColor) {
    return (
        (instrColor === "white" &&
            !isBranchIns(instr) &&
            !isSomeInsIdontCare(instr)) ||
        globalState.print_all_compile_ins
    );
}

function printInstrCompileDebugInfo(
    instr,
    handleBeforeResult,
    handleAfterResult
) {
    let mnemonic = instr.mnemonic;
    let operands = instr.operands;
    // Determine overall instruction color based on which handlers are present.
    let instrColor = "white";
    if (globalState.letsgo || globalState.ignore_letsgo_in_printDebugInfo) {
        let prefix = "[+] ";

        if (handleBeforeResult.length > 0 && handleAfterResult.length > 0) {
            instrColor = "red";
            prefix = "";
        } else if (handleBeforeResult.length > 0) {
            instrColor = "yellow";
            prefix = "";
        } else if (handleAfterResult.length > 0) {
            instrColor = "green";
            prefix = "";
        }

        let tmp = Process.findModuleByAddress(instr.address);
        let moduleInfo =
            tmp !== null
                ? ` ${tmp.name} ${tmp.base} ${instr.address.sub(tmp.base)}`
                : "";

        // Enumerate operands
        let extra = "(" + operands.length;
        for (let i = 0; i < operands.length; i++) {
            extra += " " + operands[i].type;
        }
        extra += ")";

        if (isPrintDebugInfo(instr, instrColor)) {
            colorLog(
                prefix +
                    instr.address +
                    ": " +
                    instr.toString() +
                    " " +
                    extra +
                    moduleInfo,
                instrColor
            );

            // Print the handler lists in their specific colors.
            if (handleBeforeResult.length > 0) {
                // Using yellow for "before" handlers.
                colorLog("  " + handleBeforeResult.join(", "), "yellow");
            }
            if (handleAfterResult.length > 0) {
                // Using green for "after" handlers.
                colorLog("  " + handleAfterResult.join(", "), "green");
            }
        }
    }
}

function printInsWithModuleInfo(instr, color = "white") {
    let tmp = Process.findModuleByAddress(instr.address);
    let moduleInfo =
        tmp !== null
            ? ` ${tmp.name} ${tmp.base} ${instr.address.sub(tmp.base)}`
            : "";

    colorLog(instr.address + ": " + instr.toString() + moduleInfo, color);
}

function bug_fix_ios(){
    if (Process.platform === "darwin") {
        console.log("bug fix ios");
        libdispatchdylib = Process.findModuleByName("libdispatch.dylib");
    }
}

export function start_taint() {
    let tid = Process.getCurrentThreadId();
    if (tid == null) {
        assert(null, false, "Error: Unable to get current thread ID.");
        return;
    }

    if (globalState.TAINT_START_POS == null || globalState.TAINT_STOP_POS == null) {
        assert(null, false, "Error: Taint start or stop position is null.");
        return;
    }

    Stalker.follow(tid, {
        transform: function (iterator) {
            /*
            iterator.keep               
            iterator.memoryAccess       
            iterator.next               
            iterator.putCallout         
            iterator.putChainingReturn 
            */
            let instr = null;

            try {
                while (true) {
                    instr = iterator.next();
                    if (globalState.print_all_instr_json && globalState.letsgo) {
                        colorLog(JSON.stringify(instr), "cyan");
                    }
                    // Stalker.unfollow(tid);
                    if (instr == null) {
                        break;
                    }
                    // }

                    // do {

                    // how do we handle/save pc(this pc must not be real pc), and all registers? before we call original ins, we need to make sure registers are ready. (just curious how frida stalker gum handle this)

                    // FIXME: just a bookmark here

                    // console.log(JSON.stringify(instr));
                    if (globalState.letsgo == false) {
                        let newLetsgo = checkTaintStart(instr, iterator);
                        if (newLetsgo !== globalState.letsgo) {
                            colorLog(`letsgostatus change: false -> true, instr: ${instr.address} : ${instr.toString()}`, "green");
                        }
                        globalState.letsgo = newLetsgo;
                        // No longer needed - direct globalState access(globalState.mem, globalState.regs, globalState.letsgo);
                    } else {
                        let newLetsgo = checkTaintStop(instr, iterator);
                        if (newLetsgo !== globalState.letsgo) {
                            colorLog(`letsgostatus change: true -> false, instr: ${instr.address} : ${instr.toString()}`, "red");
                        }
                        globalState.letsgo = newLetsgo;
                        // No longer needed - direct globalState access(globalState.mem, globalState.regs, globalState.letsgo);
                    }

                    // can we do unfollow inside stalker? i think we can its just compile phrase, after each bb compiled, the code can run, and when it runs, it unfollows and return back to original next bb. but the question is if we unfollow from the middle of bb. we actually compilled all the bb, so we just jump to origianl bb and continue run from there or we exec the whole bb after that we do unfollow. we can test it by seeing if code run after unfollow or not.

                    // // this must be put before interator.keep(), because if we meet branch ins, our callout will be lost.
                    // if (stalker_unfollow && !stalker_unfollow_put) {
                    //     colorLog("we found stalker_unfollow is true", "red");
                    //     stalker_unfollow_put = true;
                    //     iterator.putCallout(function (ctx) {
                    //         let instr = Instruction.parse(ctx.pc);
                    //         // colorLog(JSON.stringify(instr), "red");
                    //         colorLog("stalker unfollowed at " + instr.address + ": " + instr.toString(), "red");
                    //         // why we do unfollow in callout? is because callout is in runtime phrase. we can also call unfollow in compile phrase. but the previous callouts compiled will not be executed. normally we get exception in runtime phrase, but that runtime is already compiled before running. so we have to compile unfollow in next bb.
                    //         Stalker.unfollow(tid);
                    //     });
                    //     colorLog("we put callout at " + instr.address + ": " + instr.toString(), "red");
                    // }
                    if (Process.platform === "darwin") {
                        // console.log("libdispatchdylib", libdispatchdylib.name, libdispatchdylib.base, libdispatchdylib.size);
                        // instr.address in libdispatchdylib
                        if (instr.address.sub(libdispatchdylib.base) >= 0 && instr.address.sub(libdispatchdylib.base) < libdispatchdylib.size) {
                            // console.log("instr.address", instr.address);
                            // console.log("libdispatchdylib contains", instr.address);
                            iterator.keep();
                            continue;
                        }
                    }

                    let handleBeforeResult = handleBeforeKeep(instr, iterator);
                    iterator.keep();
                    let handleAfterResult = handleAfterKeep(instr, iterator);

                    printInstrCompileDebugInfo(
                        instr,
                        handleBeforeResult,
                        handleAfterResult
                    );

                    // } while ((instr = iterator.next()) !== null);
                }
            } catch (err) {
                colorLog("******* " + err, "red");
                // colorLog(err);
            }

            if (globalState.letsgo && globalState.show_bb_seperator)
                console.log("-------------------------------"); // bb seperator
        },
    });
}

/////////// functions /////////////
function returnObjectEntries(obj) {
    return Object.getOwnPropertyNames(obj);
}

// console.log(`\x1b[31m aaaa ${operands[0].value} \x1b[0m`); // TODO: we wrap this function, the first parameter is color




// parseVector function removed - using imported version from utils.js

// taintSIMDRegFromReg function removed - using imported version from utils.js

// taintSIMDRegFromMem function removed - using imported version from utils.js

// taintMemFromSIMDReg function removed - using imported version from utils.js


// this function returns ptr or ArrayBuffer. its because frida returns ptr for general purpose registers and ArrayBuffer for SIMD registers.

function hexStringOfRegVal(regVal) {
    // If the value is an ArrayBuffer (e.g. from a q register)
    if (regVal instanceof ArrayBuffer) {
        const bytes = new Uint8Array(regVal);
        let hexStr = "0x";
        for (let i = 0; i < bytes.length; i++) {
            hexStr += bytes[i].toString(16).padStart(2, "0");
        }
        return hexStr;
    }

    // Otherwise, assume it's a pointer object (from x/w registers)
    // pointer.toString() returns the hex representation (e.g., "0x7ffdeadbeef")
    let pointerHex = regVal.toString();
    if (!pointerHex.startsWith("0x")) {
        pointerHex = "0x" + pointerHex;
    }
    return pointerHex;
}






function makeSureNoVRegs(ctx) {
    return;
    let instr = Instruction.parse(ctx.pc);
    let operands = instr.operands;

    for (let i = 0; i < operands.length; i++) {
        if (operands[i].type === "reg") {
            let regName = operands[i].value;
            if (regName.startsWith("v")) {
                assert(
                    ctx,
                    false,
                    "Error: SIMD register " + regName + " is not supported."
                );
            }
        }
    }
}

// checkNZCVFlag function removed - using imported version from utils.js

/////////// taint functions /////////////

function debugOnSpecificIns(instr, iterator) {
    iteratorPutCalloutWrapper(
        instr,
        iterator,
        debugOnSpecificInsCallout,
        debugOnSpecificInsCallout
    );
    return "";

    function debugOnSpecificInsCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        let instr_list = ["aese", "dup", "st1", "eor"];

        if (instr_list.includes(mnemonic)) {
            colorLog(instr.address + ": " + instr.toString(), "blue");
            colorLog(JSON.stringify(ctx), "magenta");
            colorLog(JSON.stringify(instr), "magenta");
        }
    }
}

function printInstrDuringRuntime(instr, iterator) {
    iteratorPutCalloutWrapper(instr, iterator, printInstrDuringRuntimeCallout);
    return "";

    function printInstrDuringRuntimeCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);

        // print ctx
        // colorLog(JSON.stringify(ctx), "white");
        // colorLog("", "white");
        let tmp = Process.findModuleByAddress(instr.address);
        let moduleInfo =
            tmp !== null
                ? ` ${tmp.name} ${tmp.base} ${instr.address.sub(tmp.base)}`
                : "";
        colorLog(instr.address + ": " + instr.toString() + moduleInfo, "blue");
    }
}

function showRegMemStatus(instr, iterator) {
    // print out reg and mem status
    iteratorPutCalloutWrapper(instr, iterator, showRegMemStatusCallout);
    return "";

    function showRegMemStatusCallout(ctx) {
        if (!globalState.letsgo) return;

        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        let oplen = operands.length;

        // FIXME: delete this after handling this ins
        // if (instr.mnemonic === "dup" && instr.opStr === "v6.4s, v3.s[3]") { // we dont handle this for now
        //     return
        // }

        for (let i = 0; i < oplen; i++) {
            if (operands[i].type === "reg") {
                let {
                    name: name,
                    regVal: regVal,
                    regOrignVal: regOrignVal,
                    shift: shift,
                    ext: ext,
                    vas: vas,
                } = parseRegOperand(ctx, operands[i]);

                if (name) colorLog("name: " + name, "cyan");
                if (shift) colorLog("shift: " + JSON.stringify(shift), "cyan");
                if (ext) colorLog("ext: " + ext, "cyan");
                if (regVal)
                    colorLog("regVal: " + hexStringOfRegVal(regVal), "cyan");
                if (regOrignVal && regOrignVal != regVal)
                    colorLog(
                        "regOrignVal: " + hexStringOfRegVal(regOrignVal),
                        "cyan"
                    );
                if (vas) colorLog("vas: " + vas, "cyan");
            } else if (operands[i].type === "mem") {
                let {
                    memAddr: memAddr,
                    isIndirectTainted: isIndirectTainted,
                    base: base,
                    disp: disp,
                    index: index,
                    shift: shift,
                    ext: ext,
                } = parseMemOperand(ctx, operands[i]);

                colorLog("---", "cyan");
                if (base)
                    colorLog("base: " + base.name + " " + base.regVal, "cyan");
                if (disp) colorLog("disp: " + disp, "cyan");
                if (index)
                    colorLog(
                        "index: " + index.name + " " + index.regVal,
                        "cyan"
                    );
                if (shift) colorLog("shift: " + JSON.stringify(shift), "cyan");
                if (ext) colorLog("ext: " + ext, "cyan");

                colorLog("isIndirectTainted: " + isIndirectTainted, "cyan");
                colorLog("mem: " + memAddr, "cyan");
            }
        }
        colorLog("===", "cyan");
    }
}

// this should be registered before taint propagation
function showTaintStatusWhenTouchingTaint(instr, iterator) {
    iteratorPutCalloutWrapper(
        instr,
        iterator,
        showTaintStatusWhenTouchingTaintCallout
    );
    // we return "" is because we dont want to make this debug function showing ins is handled.
    return "";

    function showTaintStatusWhenTouchingTaintCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        // colorLog("showTaintStatusWhenTouchingTaintCallout", "magenta");
        // colorLog(instr.address + ": " + instr.toString(), "magenta");

        // FIXME: delete this after handling this ins
        // if (instr.mnemonic === "dup" && instr.opStr === "v6.4s, v3.s[3]") { // we dont handle this for now
        //     return
        // }

        let oplen = operands.length;
        // if (globalState.REG_TAINT !== globalState.regs.toArray().toString() || globalState.MEM_TAINT !== globalState.mem.toArray().toString()) {
        // find minopsize here
        let memSize = 16;
        for (let i = 0; i < oplen; i++) {
            if (operands[i].type === "reg") {
                let reg = operands[i].value;
                let regSize = globalState.regs.arch.registers[reg][1];
                if (regSize < memSize) {
                    memSize = regSize;
                }
            }
        }

        let isTouchingTaint = false;
        for (let i = 0; i < oplen; i++) {
            // if (operands[i].type === "reg") {
            //     let {name: name, regOrignVal: regOrignVal, regVal: regVal} = parseRegOperand(ctx, operands[i]);
            //     if (globalState.regs.isTainted(name) || globalState.mem.isTainted(regVal, memSize) || globalState.mem.isTainted(regOrignVal, memSize)) {
            //         isTouchingTaint = true;
            //     }
            // } else if (operands[i].type === "mem") {
            //     let { memAddr: memAddr, isIndirectTainted: isIndirectTainted, base: base, disp: disp, index: index, shift: shift, ext: ext} = parseMemOperand(ctx, operands[i]);

            //     if (globalState.mem.isTainted(memAddr, memSize) || isIndirectTainted) {
            //         isTouchingTaint = true;
            //     }
            // }

            if (operands[i].type === "reg") {
                let {
                    name: name,
                    regOrignVal: regOrignVal,
                    regVal: regVal,
                } = parseRegOperand(ctx, operands[i]);
                // if (globalState.regs.isTainted(name)) {
                if (
                    globalState.regs.isTainted(name) ||
                    globalState.mem.isTainted(regVal, memSize) ||
                    globalState.mem.isTainted(regOrignVal, memSize)
                ) {
                    isTouchingTaint = true;
                }
            } else if (operands[i].type === "mem") {
                let {
                    memAddr: memAddr,
                    isIndirectTainted: isIndirectTainted,
                    base: base,
                    disp: disp,
                    index: index,
                    shift: shift,
                    ext: ext,
                } = parseMemOperand(ctx, operands[i]);
                if (globalState.mem.isTainted(memAddr, memSize) || isIndirectTainted) {
                    isTouchingTaint = true;
                }
            }
        }

        if (isTouchingTaint) {
            colorLog("***", "magenta");
            colorLog("reg taint: " + globalState.regs.toArray(), "magenta");
            globalState.REG_TAINT = globalState.regs.toArray().toString();
            colorLog("mem taint: " + globalState.mem.toArray(), "magenta");
            globalState.MEM_TAINT = globalState.mem.toArray().toString();
            colorLog("", "white");
        }
    }
}

function showTaintStatusWhenUpdate(instr, iterator) {
    // if regs or mem is tainted, we need to print them out.
    // we only do this before the instruction is executed. otherwise mem addr might be wrong.

    // for example
    // 0x5bd8c28e34: ldrb w8, [x8, x9]
    // reg: x8 0x5bd8c2b840
    // mem: 0x5bd8c2b840
    // mem is tainted 0x5bd8c2b840 minopsize 4
    // reg taint: x8(1.0.0.0.0.0.0.0),w8(1.0.0.0.0.0.0.0)
    // mem taint: 0x5bd8c2b840,0x5bd8c2b841

    // reg: x8 0x61
    // mem: 0x61
    // reg taint: x8(1.0.0.0.0.0.0.0),w8(1.0.0.0.0.0.0.0)
    // mem taint: 0x5bd8c2b840,0x5bd8c2b841

    iteratorPutCalloutWrapper(instr, iterator, showTaintStatusWhenUpdateCallout);
    return "";

    function showTaintStatusWhenUpdateCallout(ctx) {
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        if (
            globalState.REG_TAINT !== globalState.regs.toArray().toString() ||
            globalState.MEM_TAINT !== globalState.mem.toArray().toString()
        ) {
            colorLog("reg taint: " + globalState.regs.toArray(), "green");
            globalState.REG_TAINT = globalState.regs.toArray().toString();
            colorLog("mem taint: " + globalState.mem.toArray(), "green");
            globalState.MEM_TAINT = globalState.mem.toArray().toString();
            colorLog("", "white");
        }
    }
}

function checkIfStalkerUnfollow(instr, iterator) {
    iteratorPutCalloutWrapper(
        instr,
        iterator,
        checkIfStalkerUnfollowCallout,
        checkIfStalkerUnfollowCallout
    );
    return "";

    function checkIfStalkerUnfollowCallout(ctx) {
        if (!globalState.letsgo) return;
        let addr = ctx.pc;
        let instr = Instruction.parse(addr);
        if (addr.equals(globalState.stalker_unfollow_addr)) {
            colorLog(
                "we unfollow here -> " +
                    instr.address +
                    ": " +
                    instr.toString(),
                "red"
            );
            Stalker.unfollow();
        }
    }
}

function customHandleOnInstruction(instr, iterator) {
    iteratorPutCalloutWrapper(
        instr,
        iterator,
        customHandleOnInstructionCallout,
        customHandleOnInstructionCallout
    );
    return "";

    function customHandleOnInstructionCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;
        for (let i = 0; i < operands.length; i++) {
            if (operands[i].type === "reg") {
                if (operands[i].vectorIndex != null) {
                    colorLog("OKOK" + JSON.stringify(operands[i]), "red");
                    colorLog(JSON.stringify(instr), "red");
                }
            }
        }
    }
}

function printRunningInstruction(instr, iterator) {
    var mnemonic = instr.mnemonic;
    if (mnemonic === "ldaxr" || mnemonic === "stlxr" || mnemonic === "ldar" || mnemonic === "cmp" || mnemonic === "cbnz" || mnemonic === "b.ne" || mnemonic === "ldxr" || mnemonic === "stxr" || mnemonic === "cbz" || mnemonic.startsWith("b") || mnemonic === "ubfx") return "";
    // if operands is x16, we just return
    if (instr.operands[0] && instr.operands[0].type === "reg" && (instr.operands[0].value.startsWith("x16") || instr.operands[0].value.startsWith("x17"))) return "";

    iteratorPutCalloutWrapper(instr, iterator, printRunningInstructionCallout, printRunningInstructionCallout);
    return "";

    function printRunningInstructionCallout(ctx) {
        // if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        colorLog(JSON.stringify(instr), "red");
    }
}

function handleInstruction(instr, iterator, ins_list) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    for (let ins of ins_list) {
        if (mnemonic === ins.mnemonic) {
            if (operands.length === ins.operands.length) {
                let handled = true;
                for (let i = 0; i < operands.length; i++) {
                    if (operands[i].type !== ins.operands[i]) {
                        handled = false;
                        break;
                    }
                }
                if (handled) {
                    return iteratorPutCalloutWrapper(
                        instr,
                        iterator,
                        ins.callout
                    );
                }
            }
        }
    }
    return null;
}

// TODO: we have problem here, is this function called before ins executed or after?
// so after testing, we found that if we put the callout before the instruction, it will be called before the instruction, and vice versa.

///////// 5.1 Control Flow /////////


// TODO: handle syscall
// and handle simple lib functions like strcpy, memcpy to increase performance

// TODO: we can do a statistic here, like what mnemonic we got, and what type of operands, how many operands we have, etc.
function instrStatistic(instr) {
    return null;
}

function checkTaintStart(instr, iterator) {
    if (instr.address.equals(globalState.TAINT_START_POS)) {
        colorLog(
            `Taint started at ins *** ${
                instr.address
            } : ${instr.toString()} ***`,
            "blue"
        );

        iteratorPutCalloutWrapper(instr, iterator, taintStartCallout);

        function taintStartCallout(ctx) {
            let instr = Instruction.parse(ctx.pc);
            // colorLog(
            //     "Taint start running from here: " +
            //         instr.address +
            //         " " +
            //         instr.toString(),
            //     "blue"
            // );
            globalState.mem.clear();
            globalState.regs.clear();
            // TODO: be careful with address here, its pointer object, not int value, so we cant compare using ===. checking mem implementation
            globalState.mem.taint(ctx.x0, ctx.x1);
            // globalState.regs.taint('x0'); // TODO: remove this later, we just want to see where it use taints
            colorLog(
                "source -> " +
                    "x0: " +
                    ctx.x0 +
                    ", x1: " +
                    ctx.x1 +
                    ", x2: " +
                    ctx.x2 +
                    ", x3: " +
                    ctx.x3,
                "blue"
            );
            colorLog("mem tainted: ", "blue");
            colorLog(globalState.mem.toArray() + "\n", "blue");
            colorLog("regs tainted: ", "blue");
            colorLog(globalState.regs.toArray() + "\n", "blue");
            globalState.REG_TAINT = globalState.regs.toArray().toString();
            globalState.MEM_TAINT = globalState.mem.toArray().toString();
            // globalState.letsgo = true;
        }

        return true;
    }
    return false;
}

function checkTaintStop(instr, iterator) {
    if (instr.address.equals(globalState.TAINT_STOP_POS)) {
        colorLog(
            `Taint stopped at ins *** ${
                instr.address
            } : ${instr.toString()} ***`,
            "blue"
        );

        iteratorPutCalloutWrapper(instr, iterator, taintStopCallout);

        function taintStopCallout(ctx) {
            let instr = Instruction.parse(ctx.pc);
            // colorLog(
            //     "Taint stopped running from here: " +
            //         instr.address +
            //         " " +
            //         instr.toString(),
            //     "blue"
            // );

            colorLog("sink -> " + "x0: " + ctx.x0 + ", x1: " + ctx.x1, "blue");
            if (globalState.mem.isFullyTainted(ctx.x0, ctx.x1)) {
                colorLog("output_buffer is fully tainted", "red");
            } else if (globalState.mem.isTainted(ctx.x0, ctx.x1)) {
                colorLog("output_buffer is partially tainted", "yellow");
            } else {
                colorLog("output_buffer is not tainted", "green");
            }

            colorLog("mem tainted: ", "blue");
            colorLog(globalState.mem.toArray() + "\n", "blue");
            colorLog("regs tainted: ", "blue");
            colorLog(globalState.regs.toArray() + "\n", "blue");
            // globalState.letsgo = false;
        }

        // colorLog(instr.address + ": " + globalState.TAINT_STOP_POS, "blue");
        // Stalker.unfollow() // TODO: we cant unfollow here, coz its compile phrase. if we stop here, the callout before wont be called. we can return a signal and let transformer call unfollow when instr.next is null.
        return false;
    }

    return true;
}

function registerStalkerHandle(handle) {
    if (globalState.registerStalkerHandleIsOn) {
        globalState.stalkerHandleList.push(handle);
    } else {
        console.log("registerStalkerHandle is off");
    }
}

function handleBeforeKeep(instr, iterator) {
    let handleResult = [];
    // if (!globalState.letsgo) return handleResult;

    for (let i = 0; i < globalState.stalkerHandleList.length; i++) {
        // check if element has onEnter, then call it
        if (globalState.stalkerHandleList[i].onEnter) {
            let tmpResult = globalState.stalkerHandleList[i].onEnter(instr, iterator);
            if (tmpResult) {
                handleResult.push(tmpResult);
            }
        }
    }

    return handleResult;
}

function handleAfterKeep(instr, iterator) {
    let handleResult = [];
    // if (!globalState.letsgo) return handleResult;

    for (let i = 0; i < globalState.stalkerHandleList.length; i++) {
        // check if element has onEnter, then call it
        if (globalState.stalkerHandleList[i].onLeave) {
            let tmpResult = globalState.stalkerHandleList[i].onLeave(instr, iterator);
            if (tmpResult) {
                handleResult.push(tmpResult);
            }
        }
    }

    return handleResult;
}
