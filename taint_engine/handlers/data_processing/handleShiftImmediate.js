import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseImmOperand,
    globalState
} from '../../utils.js';

/*
5.3.7 Shift (immediate)
*/
function handleShiftImmediate(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;
    // TODO: think about shift operation, we might also need to shift the taint data, but only based on byte level. we will calculate which bytes to be tainted based on the shift amount
    if (
        mnemonic === "lsr" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, lsrRegRegImmCallout);
    }

    if (
        mnemonic === "lsl" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, lslRegRegImmCallout);
    }

    function lsrRegRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;
        let { immVal: immVal, shift: shift } = parseImmOperand(
            ctx,
            operands[2]
        );
        // if op1 is tainted, we taint whole op0
        
        if (globalState.regs.isTainted(src)) {
            globalState.regs.taint(dest);
        } 
        // TODO: else should we untaint the dest register?
    }

    function lslRegRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;
        let { immVal: immVal, shift: shift } = parseImmOperand(
            ctx,
            operands[2]
        );
        // if op1 is tainted, we taint whole op0
        if (globalState.regs.isTainted(src)) {
            globalState.regs.taint(dest);
        }
        // TODO: else should we untaint the dest register?
    }

    if (
        mnemonic === "ror" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, rorRegRegImmCallout);
    }

    function rorRegRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;
        let { immVal: immVal, shift: shift } = parseImmOperand(
            ctx,
            operands[2]
        );

        // ROR: Rotate right
        // For taint analysis, propagate taint from source to destination
        if (globalState.regs.isTainted(src)) {
            globalState.regs.taint(dest);
        } else {
            globalState.regs.untaint(dest);
        }
    }

    if (
        mnemonic === "asr" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, asrRegRegImmCallout);
    }

    function asrRegRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;
        let { immVal: immVal, shift: shift } = parseImmOperand(
            ctx,
            operands[2]
        );
        
        // ASR: Arithmetic shift right (sign-extend)
        // if source is tainted, we taint destination
        if (globalState.regs.isTainted(src)) {
            globalState.regs.taint(dest);
        }
    }

    return null;
}

export { handleShiftImmediate };
