import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    globalState
} from '../../utils.js';

/*
5.6.4 Floating-point Convert
*/
function handleFloatingPointConvert(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "scvtf" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, scvtfRegRegCallout);
    }

    if (
        mnemonic === "ucvtf" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ucvtfRegRegCallout);
    }

    if (
        mnemonic === "fcvt" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, fcvtRegRegCallout);
    }

    if (
        mnemonic === "fcvtzs" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, fcvtzsRegRegCallout);
    }

    function scvtfRegRegCallout(ctx) {
        // signed integer to floating pointinstructionimplementation
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;

        // signed integer to floating point：target register inherits source register taint
        globalState.regs.spread(dest, src);
    }

    function ucvtfRegRegCallout(ctx) {
        // unsigned integer to floating pointinstructionimplementation
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;

        // unsigned integer to floating point：target register inherits source register taint
        globalState.regs.spread(dest, src);
    }

    function fcvtRegRegCallout(ctx) {
        // floating point format conversioninstructionimplementation
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;

        // floating point conversion：target register inherits source register taint
        globalState.regs.spread(dest, src);
    }

    function fcvtzsRegRegCallout(ctx) {
        // floating point to signed integerinstructionimplementation
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;

        // floating point to signed integer：target register inherits source register taint
        globalState.regs.spread(dest, src);
    }

    return null;
}

export { handleFloatingPointConvert };
