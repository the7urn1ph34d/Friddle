// Utility functions and variables for taint engine handlers
import * as arch from "./core/arm64.js";
import { Memory as TaintMemory, Registers as TaintRegisters } from "./core/core.js";

// Global state object containing all shared state
export const globalState = {
    // Core taint analysis objects
    mem: null,
    regs: null,
    letsgo: false,
    
    // Stalker related
    stalkerHandleList: null,
    stalker_unfollow_addr: null,
    registerStalkerHandleIsOn: false,
    
    // Taint tracking positions
    TAINT_START_POS: null,
    TAINT_STOP_POS: null,
    REG_TAINT: "",
    MEM_TAINT: "",
    
    // Taint analysis configuration
    enableImplicitTaint: true,  // Enable implicit flow tracking by default
    
    // Debug configuration
    show_bb_seperator: false,
    print_all_compile_ins: false,
    print_all_instr_json: false,
    ignore_letsgo_in_printDebugInfo: false,
};

// Note: Instruction is available globally in Frida, no need to import

// Initialize all global state - called from taint_engine.js
export function initializeUtils() {
    console.log("initializeUtils");
    globalState.mem = new TaintMemory();
    globalState.regs = new TaintRegisters(arch);
    globalState.letsgo = false;
    globalState.stalkerHandleList = [];
    globalState.TAINT_START_POS = null;
    globalState.TAINT_STOP_POS = null;
    globalState.REG_TAINT = "";
    globalState.MEM_TAINT = "";
    // Keep existing debug configuration, don't reset
    globalState.show_bb_seperator = false;
    globalState.print_all_compile_ins = false;
    globalState.print_all_instr_json = false;
    globalState.ignore_letsgo_in_printDebugInfo = false;
    globalState.stalker_unfollow_addr = ptr(0);
    globalState.registerStalkerHandleIsOn = true;
}

// Export utility functions (will be extracted from taint_engine.js)
export function colorLog(str, color = null) {
    switch (color) {
        case "red":
            console.log(`\x1b[31m${str}\x1b[0m`);
            break;
        case "green":
            console.log(`\x1b[32m${str}\x1b[0m`);
            break;
        case "yellow":
            console.log(`\x1b[33m${str}\x1b[0m`);
            break;
        case "blue":
            console.log(`\x1b[34m${str}\x1b[0m`);
            break;
        case "magenta":
            console.log(`\x1b[35m${str}\x1b[0m`);
            break;
        case "cyan":
            console.log(`\x1b[36m${str}\x1b[0m`);
            break;
        case "gray":
            console.log(`\x1b[90m${str}\x1b[0m`);
            break;
        case "white":
        default:
            console.log(str);
    }
}

// Helper function for iteratorPutCalloutWrapper
function isSIMD(instr) {
    let operands = instr.operands;
    for (let i = 0; i < operands.length; i++) {
        let op = operands[i];
        if (op.type === "reg") {
            let regName = operands[i].value;
            // for q, d, s registers they are FP registers not SIMD registers
            if (regName.startsWith("v")) {
                return true;
            }
        }
    }
    return false;
}

export function iteratorPutCalloutWrapper(
    instr,
    iterator,
    noSIMDCallout = null,
    SIMDCallout = null
) {
    // TODO: we can have callout function wrapper here. which means we can do something called before and after the callout. and using some info we can get during compile phrase. could also be used to improve performance. and they can also be used on debugging, instead of registering them in callout. we can also pass those info to callout

    function noSIMDStub(ctx) {
        if (!globalState.letsgo) return;
        assert(
            ctx,
            false,
            "Error: found no SIMD register but no SIMD callout is null"
        );
    }

    function SIMDStub(ctx) {
        if (!globalState.letsgo) return;
        assert(
            ctx,
            false,
            "Error: found SIMD register but SIMD callout is null"
        );
    }

    let whiteList = ["eor"];

    let func_name = [];
    let handle_position = new Error().stack.split("\n")[2].trim();
    let put_callout = false;

    // if (letsgo) colorLog("instr is " + instr.toString() + " isSIMD(instr) is " + isSIMD(instr) + " noSIMDCallout is " + !(noSIMDCallout == null) + " SIMDCallout is " + !(SIMDCallout == null) + " at " + handle_position, "white");

    if (isSIMD(instr)) {
        assert(null, SIMDCallout != null, "[compile] current instr is SIMD, SIMDCallout should not be null -> " + JSON.stringify(instr));
        if (SIMDCallout) {
            func_name.push(SIMDCallout.name);
            iterator.putCallout(SIMDCallout);
            put_callout = true;
            // if (letsgo) colorLog("put SIMDCallout at " + instr.toString(), "green");
        } else {
            // iterator.putCallout(SIMDStub);
            // if (letsgo) colorLog("do not put SIMDStub at " + instr.toString(), "red");
        }

        if (noSIMDCallout) {
            // if (letsgo && !whiteList.includes(instr.mnemonic))
            //     colorLog(
            //         "why noSIMDCallout is not null when we have SIMD register? " +
            //             instr.toString() +
            //             " at " +
            //             handle_position,
            //         "red"
            //     );
        }
    } else {
        assert(null, noSIMDCallout != null, "[compile] current instr is not SIMD, noSIMDCallout should not be null -> " + JSON.stringify(instr));
        if (noSIMDCallout) {
            func_name.push(noSIMDCallout.name);
            iterator.putCallout(noSIMDCallout);
            // if (letsgo) colorLog("put noSIMDCallout at " + instr.toString(), "blue");
            put_callout = true;
        } else {
            // iterator.putCallout(noSIMDStub);
            // if (letsgo) colorLog("do not put noSIMDStub at " + instr.toString(), "red");
        }

        if (SIMDCallout) {
            // if (letsgo && !whiteList.includes(instr.mnemonic))
                // colorLog(
                //     "why SIMDCallout is not null when we have no SIMD register? " +
                //         instr.toString() +
                //         " at " +
                //         handle_position,
                //     "red"
                // );
        }
    }

    if (put_callout) {
        return func_name.toString() + " -> " + handle_position;
    } else {
        return null;
    }
}

export function readMemVal(ctx, memAddr, size) {
    switch (size) {
        case 1:
            return memAddr.toUInt8();
        case 2:
            return memAddr.toUInt16();
        case 4:
            return memAddr.toUInt32();
        case 8:
            return memAddr.toUInt64();
        default:
            assert(ctx, false, "Error: unknown size " + size);
    }
}

export function assert(ctx, condition, message) {
    // TODO: it would be better if assert have ctx
    if (!condition) {
        // stalker_unfollow = true;
        // colorLog("we set stalker unfollow to true", "red");
        if (ctx) {
            var instr = Instruction.parse(ctx.pc);
            colorLog(
                "assert failed at " + instr.address + ": " + instr.toString(),
                "red"
            );
            colorLog("ctx: " + JSON.stringify(ctx), "red");
            colorLog("instr: " + JSON.stringify(instr), "green");
        }
        Stalker.unfollow();
        throw new Error(message || "Assertion failed");
    }

    // Stalker.unfollow(); // TODO: we simply do unflow here. but we need to unflow only when we are in the middle of a bb. so we need to check if we are in the middle of a bb or not.
}

// Helper function for parseMemOperand and parseRegOperand
function ensurePtr(ctx, val, debugInfo) {
    assert(
        ctx,
        !(val instanceof ArrayBuffer),
        // "Error: Register " + debugInfo + " is a SIMD register."
        "Error: parameter is an array buffer" + debugInfo
    );
    assert(
        ctx,
        typeof val === "object" && typeof val.add === "function",
        // "Error: Register " + debugInfo + " value is not a pointer."
        "Error: parameter is not a pointer" + debugInfo
    );
    return val;
    // exit
}

// Helper function for parseMemOperand and parseRegOperand
function readRegVal(ctx, reg) {
    if (reg === "xzr" || reg === "wzr") {
        return ptr(0);
    }

    // Determine the desired size and map the register to its underlying name.
    // For general-purpose registers:
    //   - "wN" registers are 32-bit (4 bytes) and map to "xN".
    //   - "xN" registers are 64-bit (8 bytes).
    // For SIMD/floating-point registers:
    //   - "sN" registers are 32-bit (4 bytes) and map to "qN".
    //   - "dN" registers are 64-bit (8 bytes) and map to "qN".
    //   - "qN" registers are 128-bit (16 bytes).
    let desiredSize;
    if (reg === "nzcv") {
        desiredSize = 4;
    } else if (reg === "sp" || reg === "lr" || reg === "fp" || reg === "pc") {
        desiredSize = 8;
    } else if (reg.startsWith("w")) {
        desiredSize = 4;
        reg = "x" + reg.slice(1);
    } else if (reg.startsWith("x")) {
        desiredSize = 8;
    } else if (reg.startsWith("s")) {
        desiredSize = 4;
        reg = "q" + reg.slice(1);
    } else if (reg.startsWith("d")) {
        desiredSize = 8;
        reg = "q" + reg.slice(1);
    } else if (reg.startsWith("q")) {
        desiredSize = 16;
    } else if (reg.startsWith("v")) {
        desiredSize = 16;
        reg = "q" + reg.slice(1);
    } else {
        assert(ctx, false, "Unknown register type: " + reg);
    }

    let val = ctx[reg]; // here frida returns ptr for general purpose registers and ArrayBuffer for SIMD registers
    // Ensure the returned value is either an ArrayBuffer or a pointer. in case frida returns other type, we assert false.
    assert(
        ctx,
        val instanceof ArrayBuffer ||
            (typeof val === "object" && typeof val.add === "function"),
        "Error: Register " + reg + " is not a pointer or an ArrayBuffer."
    );

    if (val instanceof ArrayBuffer) {
        // For SIMD registers (from q registers), return exactly desiredSize bytes.
        return val.slice(0, desiredSize);
    } else {
        // For general-purpose registers, ctx returns a pointer.
        // For "w" registers, return only the lower 32 bits of x register; for "x" registers, return the pointer as is.
        if (desiredSize === 4) {
            return ptr(val.toUInt32());
        } else {
            return val;
        }
    }
}

export function parseMemOperand(ctx, memOperand) {
    // Allowed outer keys.
    const allowedOuterKeys = new Set([
        "type",
        "value",
        "shift",
        "ext",
        "access",
    ]);
    for (const key in memOperand) {
        assert(
            ctx,
            allowedOuterKeys.has(key),
            "Unknown key in mem operand: " + key + " " + memOperand[key]
        );
    }
    // Extract inner value.
    const opVal = memOperand.value || {};
    const allowedValKeys = new Set(["base", "index", "disp"]);
    for (const key in opVal) {
        assert(
            ctx,
            allowedValKeys.has(key),
            "Unknown key in mem operand value: " + key + " " + opVal[key]
        );
    }

    let addr = ptr(0);
    let isIndirectTainted = false; // Flag for registers used in address computation

    // Process base register if present.
    let baseRegInfo = null;
    if (opVal.base) {
        assert(
            ctx,
            !opVal.base.startsWith("v"),
            "Error: Base register " + opVal.base + " is a SIMD register."
        );
        // Get the original value from readRegVal.
        let baseValOriginal = readRegVal(ctx, opVal.base);
        let baseVal = ensurePtr(ctx, baseValOriginal, opVal.base);
        addr = addr.add(baseVal);
        if (globalState.enableImplicitTaint && globalState.regs.isTainted(opVal.base)) {
            // Check if base register is tainted (only if implicit taint tracking is enabled).
            isIndirectTainted = true;
            // TODO: we can print out the log when we get indirectTainted situation.
        }
        // Store register name and its original value.
        baseRegInfo = { name: opVal.base, regVal: baseValOriginal };
    }

    // Add displacement if present.
    if (opVal.disp) {
        addr = addr.add(opVal.disp);
    }

    // Process index register if present.
    let indexRegInfo = null;
    if (opVal.index) {
        // colorLog(
        //     "in parseMemOperand and index is " + JSON.stringify(memOperand),
        //     "red"
        // );
        assert(
            ctx,
            !opVal.index.startsWith("v"),
            "Error: Index register " + opVal.index + " is a SIMD register."
        );
        let indexValOriginal = readRegVal(ctx, opVal.index);
        let indexVal = ensurePtr(ctx, indexValOriginal, opVal.index);

        if (memOperand.ext) {
            // colorLog("in parseMemOperand and ext is " + JSON.stringify(memOperand), "red"); 
            // Handle extension: uxtw or sxtw.
            if (memOperand.ext === "uxtw") {
                assert(
                    ctx,
                    opVal.index.startsWith("w"),
                    "Error: uxtw extension is only valid for 32-bit registers."
                );
                indexVal = ptr(indexVal.toUInt32());
            } else if (memOperand.ext === "sxtw") {
                assert(
                    ctx,
                    opVal.index.startsWith("w"),
                    "Error: sxtw extension is only valid for 32-bit registers."
                );
                indexVal = ptr(indexVal.toInt32());
            } else {
                assert(
                    ctx,
                    false,
                    "Error: this ext is not supported for index register " +
                        memOperand.ext
                );
            }
        }


        // TODO: we doubt about if there is shift in mem operand
        // Process shift if present.
        if (memOperand.shift) {
            // colorLog(
            //     "in parseMemOperand and shift is " + JSON.stringify(memOperand),
            //     "red"
            // );
            if (memOperand.shift.type === "lsl") {
                let shiftAmount = memOperand.shift.value;
                indexVal = indexVal.shl(shiftAmount);
            } else {
                assert(
                    ctx,
                    false,
                    "Error: this shift is not supported for index register " +
                        memOperand.shift
                );
            }
        }

        addr = addr.add(indexVal);

        // Check if index register is tainted (only if implicit taint tracking is enabled).
        if (globalState.enableImplicitTaint && globalState.regs.isTainted(opVal.index)) {
            isIndirectTainted = true;
        }
        // Store register name and its original value.
        indexRegInfo = { name: opVal.index, regVal: indexValOriginal };

        // FIXME: we have bug here. we calculate the indexVal with the original value of index register. but we never update it to addr.
        // colorLog("in parseMemOperand, addr is " + addr, "red");
        // let instr = Instruction.parse(ctx.pc);
        // colorLog(JSON.stringify(ctx), "yellow");
        // colorLog(JSON.stringify(instr), "green");
    }


    // Return detailed info for debugging.
    return {
        memAddr: addr,
        isIndirectTainted: isIndirectTainted,
        base: baseRegInfo,
        disp: opVal.disp,
        index: indexRegInfo,
        shift: memOperand.shift,
        ext: memOperand.ext, // do we really have memOperand.ext?
    };
}

export function parseRegOperand(ctx, operand) {
    // Allow "ext" along with the other keys.
    const allowedKeys = new Set([
        "type",
        "value",
        "access",
        "shift",
        "ext",
        "vas",
        "vectorIndex",
    ]);
    for (const key in operand) {
        assert(
            ctx,
            allowedKeys.has(key),
            "Unknown key in reg operand: " + key + " " + operand[key]
        );
        if (operand.vas)
            assert(
                ctx,
                operand.vas.endsWith("b") ||
                    operand.vas.endsWith("h") ||
                    operand.vas.endsWith("s") ||
                    operand.vas.endsWith("d") ||
                    operand.vas.endsWith("q"),
                "Unknown vas type in reg operand: " + operand.vas
            );
        // instr: {"address":"0x719915e79c","next":"0x719915e7a0","size":4,"mnemonic":"dup","opStr":"v6.4s, v3.s[3]","operands":[{"type":"reg","value":"v6","vas":"4s","access":"w"},{"type":"reg","value":"v3","vas":"8b","vectorIndex":3,"access":"r"}],"regsAccessed":{"read":["v3"],"written":["v6"]},"regsRead":[],"regsWritten":[],"groups":["neon"]}
    }
    if (operand.shift) {
        const allowedShiftKeys = new Set(["type", "value"]);
        for (const key in operand.shift) {
            assert(
                ctx,
                allowedShiftKeys.has(key),
                "Unknown key in reg operand shift: " +
                    key +
                    " " +
                    operand.shift[key]
            );
        }
    }

    // Get the original register name and value.
    let regName = operand.value;
    let regSize = globalState.regs.arch.registers[regName][1];
    let originalVal = readRegVal(ctx, regName);
    let computedVal = originalVal;

    // TODO: we can make handling ext and shift to a function. so that in parseMemOperand, we can reuse it.
    // If an extension is specified, ensure the value is a pointer, then apply the extension.
    if (operand.ext) {
        computedVal = ensurePtr(ctx, computedVal, regName);
        if (operand.ext === "uxtw") {
            assert(
                ctx,
                regName.startsWith("w"),
                "Error: uxtw extension is only valid for 32-bit registers."
            );
            computedVal = ptr(computedVal.toUInt32());
        } else if (operand.ext === "sxtw") {
            assert(
                ctx,
                regName.startsWith("w"),
                "Error: sxtw extension is only valid for 32-bit registers."
            );
            computedVal = ptr(computedVal.toInt32());
        } else if (operand.ext === "uxth") {
            assert(
                ctx,
                regName.startsWith("w"),
                "Error: uxth extension is only valid for 32-bit registers."
            );
            let v32 = computedVal.toUInt32();
            let low16 = v32 & 0xFFFF;
            computedVal = ptr(low16);
        } else {
            assert(
                ctx,
                false,
                "Unknown ext type in reg operand: " + operand.ext
            );
        }
    }

    // Process shift if specified.
    if (operand.shift) {
        // TODO: reg shifted here, should we also shift the taint?
        computedVal = ensurePtr(ctx, computedVal, regName);
        if (operand.shift.type === "lsl") {
            computedVal = computedVal.shl(operand.shift.value);
        } else if (operand.shift.type === "lsr") {
            computedVal = computedVal.shr(operand.shift.value);
        } else {
            assert(
                ctx,
                false,
                "Unknown shift type in reg operand: " + operand.shift.type
            );
        }
    }

    // if (operand.vectorIndex != null) {
    //     let instr = Instruction.parse(ctx.pc);
    //     colorLog("instr should be tainted with vectorIndex: " + operand.vectorIndex, "red");
    //     colorLog(JSON.stringify(instr), "green");
    // }

    return {
        name: regName,
        size: regSize,
        regVal: computedVal, // FIXME: should be operandVal here, just remember to name it right
        regOrignVal: originalVal, // FIXME: should be regVal here
        shift: operand.shift,
        ext: operand.ext,
        vas: operand.vas,
        vectorIndex: operand.vectorIndex,
    };
}

export function parseImmOperand(ctx, operand) {
    // Validate allowed operand keys.
    const allowedKeys = new Set(["type", "value", "access", "shift"]);
    for (const key in operand) {
        assert(
            ctx,
            allowedKeys.has(key),
            "Unknown key in imm operand: " + key + " " + operand[key]
        );
    }

    // Validate allowed shift keys if a shift is provided.
    if (operand.shift) {
        const allowedShiftKeys = new Set(["type", "value"]);
        for (const key in operand.shift) {
            assert(
                ctx,
                allowedShiftKeys.has(key),
                "Unknown key in imm operand shift: " +
                    key +
                    " " +
                    operand.shift[key]
            );
        }
    }

    // Save the original immediate value.
    const originalImmVal = operand.value;
    let computedImmVal = originalImmVal;

    // Apply the left shift if specified.
    if (operand.shift) {
        if (operand.shift.type === "lsl") {
            computedImmVal = ptr(computedImmVal).shl(operand.shift.value);
        } else if (operand.shift.type === "lsr") {
            computedImmVal = ptr(computedImmVal).shr(operand.shift.value);
        } else {
            assert(
                ctx,
                false,
                "Unknown shift type in imm operand: " + operand.shift.type
            );
        }
    }

    // Convert the computed immediate value to a hexadecimal string.
    const hexString = "0x" + computedImmVal.toString(16);

    return {
        immVal: computedImmVal,
        original: originalImmVal,
        shift: operand.shift,
        hex: hexString,
    };
}

export function parseVector(ctx, vector) {
    if (vector.vas == null) {
        return null;
    }

    const byteMap = { b: 1, h: 2, s: 4, d: 8 };

    const vas = vector.vas.trim().toLowerCase();
    const vectorIndex = vector.vectorIndex;
    
    let m = vas.match(/^(\d+)([bhsd])$/);
    let lanes, elementType;
    
    if (m) {
        lanes = Number(m[1]);
        elementType = m[2];
    } else {
        m = vas.match(/^([bhsd])$/);
        if (m) {
            elementType = m[1];
            lanes = 1;
        } else {
            assert(ctx, false, "Invalid VAS format: " + vector.vas);
        }
    }

    const elementBytes = byteMap[elementType];
    const vectorBytes = lanes * elementBytes;

    // sanity check
    if (lanes > 1) {
        assert(
            ctx,
            vectorBytes === 8 || vectorBytes === 16,
            "vectorBytes is not 8 or 16, instead -> " + vectorBytes
        );
    }

    return {
        vas,
        vectorIndex,
        lanes,
        elementType,
        elementBytes,
        vectorBytes,
    };
}

export function taintSIMDRegFromReg(ctx, destReg, srcReg) {
    // Note: srcReg can be either SIMD or general purpose register
    let srcVector = parseVector(ctx, srcReg);
    let destVector = parseVector(ctx, destReg);
    assert(ctx, destVector, "destReg should be SIMD register");
    
    let srcBitMap = null;
    if (srcVector){
        // FIXME: we got this nasty frida bug here
        // instr: {"address":"0x716097679c","next":"0x71609767a0","size":4,"mnemonic":"dup","opStr":"v6.4s, v3.s[3]","operands":[{"type":"reg","value":"v6","vas":"4s","access":"w"},{"type":"reg","value":"v3","vas":"8b","vectorIndex":3,"access":"r"}],"regsAccessed":{"read":["v3"],"written":["v6"]},"regsRead":[],"regsWritten":[],"groups":["neon"]}
        
        // vector register
        // assert elementBytes of srcVector and destVector are the same
        // current we only support srcLanes == 1 and srcVector.vectorIndex != null
        colorLog("*******" + JSON.stringify(srcVector), "red");
        assert(ctx, srcVector.vectorIndex != null, "srcVector.vectorIndex should not be null");
        
        // so here we use srcVectorIndex and destVector.elementBytes. because srcVector.elementBytes is 8b which is wrong. (maybe its not wrong)
        srcBitMap = globalState.regs.getBitMapWithRegOffsetAndSize(
            srcReg.name,
            srcVector.vectorIndex * destVector.elementBytes,
            destVector.elementBytes
        );
    } else {
        // general purpose register
        srcBitMap = globalState.regs.getBitMapWithRegOffsetAndSize(
            srcReg.name,
            0,
            destVector.elementBytes
        );
    }
    for (let i = 0; i < destVector.lanes; i++) {
        let offset = i * destVector.elementBytes;
        globalState.regs.setBitMapWithRegOffset(destReg.name, offset, srcBitMap);
    }
}

export function taintSIMDRegFromMem(ctx, reg, memAddr) {
    assert(ctx, reg.vas, "reg should be SIMD register");
    ensurePtr(ctx, memAddr, memAddr);
    let {
        lanes: lanes,
        elementBytes: elementBytes,
        vectorBytes: vectorBytes,
    } = parseVector(ctx, reg);
    for (let i = 0; i < lanes; i++) {
        let offset = i * elementBytes;
        let bitMap = globalState.mem.toBitMap(memAddr.add(offset), elementBytes);
        globalState.regs.setBitMapWithRegOffset(reg.name, offset, bitMap);
    }
    return vectorBytes;
}

export function taintMemFromSIMDReg(ctx, memAddr, reg) {
    assert(ctx, reg.vas, "reg should be SIMD register");
    ensurePtr(ctx, memAddr, memAddr);
    let {
        lanes: lanes,
        elementBytes: elementBytes,
        vectorBytes: vectorBytes,
    } = parseVector(ctx, reg);
    for (let i = 0; i < lanes; i++) {
        let offset = i * elementBytes;
        let ranges = globalState.regs.toRangesWithRegOffsetAndSize(
            reg.name,
            memAddr.add(offset),
            offset,
            elementBytes
        );
        globalState.mem.fromRanges(ranges);
    }
    return vectorBytes;
}

export function checkNZCVFlag(ctx) {
    let instr = Instruction.parse(ctx.pc);
    let opStr = instr.opStr;
    // Split by ", " and get the last element for the condition flag.
    let parts = opStr.split(", ");
    let flag = parts[parts.length - 1];
    let nzcv = ctx["nzcv"];
    let N = (nzcv >> 31) & 1;
    let Z = (nzcv >> 30) & 1;
    let C = (nzcv >> 29) & 1;
    let V = (nzcv >> 28) & 1;
    switch (flag) {
        case "eq": // equal: Z == 1
            return Z === 1;
        case "ne": // not equal: Z == 0
            return Z === 0;
        case "cs": // carry set (also "hs"): C == 1
        case "hs":
            return C === 1;
        case "cc": // carry clear (also "lo"): C == 0
        case "lo":
            return C === 0;
        case "mi": // negative: N == 1
            return N === 1;
        case "pl": // positive or zero: N == 0
            return N === 0;
        case "vs": // overflow: V == 1
            return V === 1;
        case "vc": // no overflow: V == 0
            return V === 0;
        case "hi": // unsigned higher: C == 1 and Z == 0
            return C === 1 && Z === 0;
        case "ls": // unsigned lower or same: C == 0 or Z == 1
            return C === 0 || Z === 1;
        case "ge": // signed greater than or equal: N equals V
            return N === V;
        case "lt": // signed less than: N does not equal V
            return N !== V;
        case "gt": // signed greater than: Z == 0 and N equals V
            return Z === 0 && N === V;
        case "le": // signed less than or equal: Z == 1 or N does not equal V
            return Z === 1 || N !== V;
        case "al": // always true
            return true;
        default:
            assert(ctx, false, "Unsupported condition flag: " + flag);
    }
}