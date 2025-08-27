import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseMemOperand,
    globalState,
    taintSIMDRegFromMem,
    taintMemFromSIMDReg
} from '../../utils.js';

/*
5.2.2 Load-Store Single Register (Unscaled Offset)
*/
function handleLoadStoreSingleRegUnscaledOffset(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "ldur" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldurRegAddrCallout);
    }

    if (
        mnemonic === "stur" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, sturRegAddrCallout);
    }

    if (
        mnemonic === "sturb" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, sturbRegAddrCallout);
    }

    if (
        mnemonic === "ldurb" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldurbRegAddrCallout);
    }

    if (
        mnemonic === "ldursw" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldurswRegAddrCallout);
    }

    function sturbRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let src = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        globalState.mem.fromRanges(globalState.regs.toRangesWithSize(src, memAddr, 1));
    }

    function ldurbRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        globalState.regs.fromBitMap(dest, globalState.mem.toBitMap(memAddr, 1));
        globalState.regs.untaintWithOffsetAndSize(dest, 1, 3);
    }

    function ldurswRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        globalState.regs.fromBitMap(dest, globalState.mem.toBitMap(memAddr, 4));
        if (globalState.mem.isTainted(memAddr, 4)) {
            // we also taint upper bits
            globalState.regs.taintWithOffsetAndSize(dest, 4, 4);
        }
    }

    function sturRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        globalState.mem.fromRanges(globalState.regs.toRanges(op0, memAddr));
    }


    function ldurRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        // let op0 = parseRegOperand(ctx, operands[0]).name;
        let op0 = parseRegOperand(ctx, operands[0]);
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        globalState.regs.fromBitMap(
            op0.name,
            globalState.mem.toBitMap(memAddr, op0.size)
        );
    }


    if (
        mnemonic === "sturh" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, sturhRegAddrCallout);
    }

    function sturhRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let src = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        // Store halfword (2 bytes) to memory
        globalState.mem.fromRanges(globalState.regs.toRangesWithSize(src, memAddr, 2));
    }

    if (
        mnemonic === "ldurh" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldurhRegAddrCallout);
    }

    function ldurhRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        
        // LDURH: Load unscaled halfword (2 bytes) from memory, clear upper bits
        globalState.regs.fromBitMap(dest, globalState.mem.toBitMap(memAddr, 2));
        globalState.regs.untaintWithOffsetAndSize(dest, 2, 2); // Clear upper 2 bytes for w register
    }

    // Added ldursh support for signed halfword load with unscaled offset
    if (
        mnemonic === "ldursh" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldurshRegAddrCallout);
    }

    if (
        mnemonic === "ldrsh" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldrshRegAddrCallout);
    }

    // 5. Memory access instruction - Callback function for ldursh instruction
    function ldurshRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let { name: dest, size: destSize } = parseRegOperand(ctx, operands[0]);
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);

        // LDURSH: Load signed halfword (2 bytes) from memory with sign extension (unscaled offset)
        globalState.regs.fromBitMap(dest, globalState.mem.toBitMap(memAddr, 2));
        if (globalState.mem.isTainted(memAddr, 2)) {
            // Sign extension: if the loaded halfword is tainted, taint the upper bits too
            if (destSize > 2) {
                // Taint remaining bytes due to sign extension
                globalState.regs.taintWithOffsetAndSize(dest, 2, destSize - 2);
            }
        }
    }

    function ldrshRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);

        // LDRSH: Load signed halfword (2 bytes) from memory with sign extension
        globalState.regs.fromBitMap(dest, globalState.mem.toBitMap(memAddr, 2));
        if (globalState.mem.isTainted(memAddr, 2)) {
            // Sign extension: if the loaded halfword is tainted, taint the upper bits too
            globalState.regs.taintWithOffsetAndSize(dest, 2, 2); // Taint upper 2 bytes for sign extension
        }
    }

    return null;
}

export { handleLoadStoreSingleRegUnscaledOffset };