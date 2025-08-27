import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseMemOperand,
    colorLog,
    globalState
} from '../../utils.js';

/*
5.2.7 Load-Store Exclusive
*/
function handleLoadStoreExclusive(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "ldxrh" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldxrhRegAddrCallout);
    }

    if (
        mnemonic === "stxrh" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, stxrhRegAddrCallout);
    }

    function stxrhRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;
        // for register in this ins we onlu have x0-x31
        // TODO: how to deal with signed extension. do we clear the upper bits or taint them? it depends if later operation use them or not(they use these information or not). i think its fine to clear them.

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        globalState.mem.fromRanges(globalState.regs.toRangesWithSize(op0, memAddr, 2));
    }

    function ldxrhRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        globalState.regs.fromBitMap(op0, globalState.mem.toBitMap(memAddr, 2));
        colorLog(
            instr.address +
                " !!!! ldxrhRegAddrCallout !!!! " +
                instr.toString(),
            "red"
        );
    }

    if (
        mnemonic === "ldxr" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldxrRegAddrCallout);
    }

    // FIXME: we cant use stxr because it will cause infinite loop. its frida bug.
    // if (
    //     mnemonic === "stxr" &&
    //     operands.length === 3 &&
    //     operands[0].type === "reg" &&
    //     operands[1].type === "reg" &&
    //     operands[2].type === "mem"
    // ) {
    //     return iteratorPutCalloutWrapper(instr, iterator, stxrRegRegAddrCallout);
    // }

    if (
        mnemonic === "ldaxr" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldaxrRegAddrCallout);
    }

    // FIXME: we cant use stlxr because it will cause infinite loop. its frida bug.
    // if (
    //     mnemonic === "stlxr" &&
    //     operands.length === 3 &&
    //     operands[0].type === "reg" &&
    //     operands[1].type === "reg" &&
    //     operands[2].type === "mem"
    // ) {
    //     return iteratorPutCalloutWrapper(instr, iterator, stlxrRegRegAddrCallout);
    // }

    function ldxrRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]);
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        
        // LDXR: Load exclusive register
        globalState.regs.fromBitMap(dest.name, globalState.mem.toBitMap(memAddr, dest.size));
    }

    function stxrRegRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let status = parseRegOperand(ctx, operands[0]).name; // Status register (0=success, 1=failure)
        let src = parseRegOperand(ctx, operands[1]);
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[2]);
        
        // STXR: Store exclusive register
        // Status register gets 0 or 1 (not tainted)
        globalState.regs.untaint(status);
        // Store the source register to memory
        globalState.mem.fromRanges(globalState.regs.toRangesWithSize(src.name, memAddr, src.size));
    }

    function ldaxrRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]);
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        
        // LDAXR: Load-acquire exclusive register
        globalState.regs.fromBitMap(dest.name, globalState.mem.toBitMap(memAddr, dest.size));
    }

    function stlxrRegRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let status = parseRegOperand(ctx, operands[0]).name; // Status register
        let src = parseRegOperand(ctx, operands[1]);
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[2]);
        
        // STLXR: Store-release exclusive register
        // Status register gets 0 or 1 (not tainted)
        globalState.regs.untaint(status);
        // Store the source register to memory
        globalState.mem.fromRanges(globalState.regs.toRangesWithSize(src.name, memAddr, src.size));
    }
    return null;
}

export { handleLoadStoreExclusive };
