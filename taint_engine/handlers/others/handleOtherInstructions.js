import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseMemOperand,
    readMemVal,
    globalState
} from '../../utils.js';

/*
9.0.0 handle instructions that not belong to any of the above categories
*/
function handleOtherInstructions(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;
    if (
        mnemonic === "casa" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, casaRegMemCallout);
    }
    function casaRegMemCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;
        let op0 = parseRegOperand(ctx, operands[0]);
        let op1 = parseRegOperand(ctx, operands[1]);
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[2]);
        // to whatever comparing situation, op0 is set to the value of memAddr. but we might need to check isIndirectTainted here.
        globalState.regs.fromBitMap(op0.name, globalState.mem.toBitMap(memAddr, op0.size));
        let memVal = readMemVal(ctx, memAddr, op0.size);
        // we update mem only when op0 equals to memVal
        if (op0.regVal.equals(memVal)) {
            globalState.mem.fromRanges(globalState.regs.toRanges(op1.name, memAddr));
        }
    }
    if (
        mnemonic === "sxtw" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, sxtwRegRegCallout);
    }
    function sxtwRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;
        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;
        // SXTW: Sign-extend word (32-bit) to doubleword (64-bit)
        // For taint analysis, we propagate taint from source to destination
        globalState.regs.spread(dest, src);
    }
    return null;
}

export { handleOtherInstructions };
