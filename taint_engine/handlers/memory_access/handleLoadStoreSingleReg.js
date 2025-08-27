import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseMemOperand,
    readMemVal,
    colorLog,
    globalState,
    parseImmOperand,
    taintSIMDRegFromMem,
    taintMemFromSIMDReg
} from '../../utils.js';

/*
5.2.1 Load-Store Single Register
*/
// TODO: make it as class, and we have many callout function in it
function handleLoadStoreSingleReg(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "ldr" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldrRegAddrCallout);
    }

    if (
        mnemonic === "ldrsb" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldrbRegAddrCallout);
    }

    if (
        mnemonic === "ldrsw" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldrswRegAddrCallout);
    }

    function ldrswRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        // for register in this ins we onlu have x0-x31
        // TODO: how to deal with signed extension. do we clear the upper bits or taint them? it depends if later operation use them or not(they use these information or not). i think its fine to clear them.
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        globalState.regs.fromBitMap(dest, globalState.mem.toBitMap(memAddr, 4));
        if (globalState.mem.isTainted(memAddr, 4)) {
            // we also taint upper bits
            globalState.regs.taintWithOffsetAndSize(dest, 4, 4);
        }
    }

    // TODO: avoid using startswith, otherwise we might have bugs and hard to debug. if we need same logic, we can put it in a function and call it
    if (
        mnemonic === "str" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, strRegAddrCallout);
    }

    if (
        mnemonic === "ldrb" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldrbRegAddrCallout);
    }

    if (
        mnemonic === "strb" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, strbRegAddrCallout);
    }

    function strbRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        let src = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        globalState.mem.fromRanges(globalState.regs.toRangesWithSize(src, memAddr, 1));
    }

    function ldrbRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);

        if (isIndirectTainted) {
            // TODO: so here, if we have indirect taint, we just taint the dest register without checking the mem addr taint status. is this correct?
            globalState.regs.taintWithOffsetAndSize(dest, 0, 1);
        } else {
            globalState.regs.fromBitMap(dest, globalState.mem.toBitMap(memAddr, 1));
        }
    }

    function strRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        let src = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        globalState.mem.fromRanges(globalState.regs.toRanges(src, memAddr));
    }


    function ldrRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);

        // colorLog("ldrRegAddrCallout: " + dest + " " + memAddr + " " + globalState.regs.arch.registers[dest], "red");
        // colorLog(JSON.stringify(ctx), "red");
        // colorLog(JSON.stringify(instr), "red");

        globalState.regs.fromBitMap(
            dest,
            globalState.mem.toBitMap(memAddr, globalState.regs.arch.registers[dest][1])
        );
    }


    if (
        mnemonic === "ldr" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldrRegAddrImmCallout);
    }

    function ldrRegAddrImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]);
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        let { immVal: immVal, shift: shift } = parseImmOperand(
            ctx,
            operands[2]
        );

        globalState.regs.fromBitMap(op0.name, globalState.mem.toBitMap(memAddr, op0.size));
    }

    if (
        mnemonic === "ldrh" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldrhRegAddrCallout);
    }

    function ldrhRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);

        // Load halfword (2 bytes) from memory, clear upper bits
        globalState.regs.fromBitMap(dest, globalState.mem.toBitMap(memAddr, 2));
        globalState.regs.untaintWithOffsetAndSize(dest, 2, 2); // Clear upper 2 bytes for w register
    }

    if (
        mnemonic === "ldrb" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldrbRegAddrImmPostCallout);
    }
    
    function ldrbRegAddrImmPostCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);

        // Load byte from memory, clear upper bits
        globalState.regs.fromBitMap(dest, globalState.mem.toBitMap(memAddr, 1));
        globalState.regs.untaintWithOffsetAndSize(dest, 1, 3); // Clear upper 3 bytes for w register
    }
    if (
        mnemonic === "strb" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, strbRegAddrImmPostCallout);
    }

    function strbRegAddrImmPostCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let src = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        
        // Store byte to memory
        globalState.mem.fromRanges(globalState.regs.toRangesWithSize(src, memAddr, 1));
    }

    if (
        mnemonic === "str" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, strRegAddrImmPostCallout);
    }

    function strRegAddrImmPostCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let src = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        
        // Store register to memory
        globalState.mem.fromRanges(globalState.regs.toRanges(src, memAddr));
    }   
    
    if (
        mnemonic === "strh" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, strhRegAddrCallout);
    }

    function strhRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let src = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);

        // Store halfword (2 bytes) to memory
        globalState.mem.fromRanges(globalState.regs.toRangesWithSize(src, memAddr, 2));
    }


    

    return null;
}

export { handleLoadStoreSingleReg };