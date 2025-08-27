import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseImmOperand,
    globalState
} from '../../utils.js';

/*
5.3.2 Logical (immediate)
*/
function handleLogicalImmediate(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "and" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, andRegRegImmCallout);
    }

    if (
        mnemonic === "ands" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, andRegRegImmCallout);
    }

    if (
        mnemonic === "orr" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, orrRegRegImmCallout);
    }

    function orrRegRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let { immVal: immVal, shift: shift } = parseImmOperand(
            ctx,
            operands[2]
        );
        globalState.regs.spread(op0, op1);
    }

    function andRegRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let { immVal: immVal, shift: shift } = parseImmOperand(
            ctx,
            operands[2]
        );
        globalState.regs.spread(op0, op1);
    }

    if (
        mnemonic === "eor" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, eorRegRegImmCallout);
    }

    function eorRegRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;
        let { immVal: immVal, shift: shift } = parseImmOperand(ctx, operands[2]);
        
        // EOR with immediate: result depends on source register
        globalState.regs.spread(dest, src);
    }

    return null;
}

export { handleLogicalImmediate };
