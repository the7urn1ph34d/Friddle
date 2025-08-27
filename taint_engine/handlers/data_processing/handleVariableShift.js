import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    globalState
} from '../../utils.js';

/*
5.4.4 Variable Shift
*/
function handleVariableShift(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "lsl" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, lslRegRegRegCallout);
    }
    if (
        mnemonic === "lsr" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, lsrRegRegRegCallout);
    }

    function lslRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;

        if (globalState.regs.isTainted(src1) || globalState.regs.isTainted(src2)) {
            globalState.regs.taint(dest);
        } else {
            // TODO: should we untaint the dest register?
            globalState.regs.untaint(dest);
        }
    }

    if (
        mnemonic === "lsr" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, lsrRegRegRegCallout);
    }

    function lsrRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;

        if (globalState.regs.isTainted(src1) || globalState.regs.isTainted(src2)) {
            globalState.regs.taint(dest);
        } else {
            // TODO: should we untaint the dest register?
            globalState.regs.untaint(dest);
        }
    }

    return null;
}

export { handleVariableShift };
