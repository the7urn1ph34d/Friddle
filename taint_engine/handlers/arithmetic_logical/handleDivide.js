import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    globalState
} from '../../utils.js';

/*
5.5.2 Divide
*/
function handleDivide(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "udiv" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, udivRegRegRegCallout);
    }

    if (
        mnemonic === "sdiv" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, udivRegRegRegCallout);
    }

    function udivRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let op2 = parseRegOperand(ctx, operands[2]).name;

        if (globalState.regs.isTainted(op1) || globalState.regs.isTainted(op2)) {
            globalState.regs.taint(op0);
        }
    }

    return null;
}

export { handleDivide };
