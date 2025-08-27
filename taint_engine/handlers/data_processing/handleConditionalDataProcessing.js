import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    globalState, 
    checkNZCVFlag
} from '../../utils.js';

/*
5.4.6 Conditional Data Processing
*/
function handleConditionalDataProcessing(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "csel" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, cselRegRegRegCallout);
    }

    if (
        mnemonic === "cset" &&
        operands.length === 1 &&
        operands[0].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, csetRegCallout);
    }

    function csetRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;

        // we simply untaint the dest register
        globalState.regs.untaint(dest);
    }

    function cselRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;

        if (checkNZCVFlag(ctx)) {
            globalState.regs.spread(dest, src1);
        } else {
            globalState.regs.spread(dest, src2);
        }
    }

    if (
        mnemonic === "cneg" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, cnegRegRegCallout);
    }

    function cnegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]);
        let op1 = parseRegOperand(ctx, operands[1]);

        // since this negative op1 to op0, we should just spread the taint from op1 to op0
        globalState.regs.spread(op0.name, op1.name);
    }

    if (
        mnemonic === "csinc" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, csincRegRegRegCallout);
    }

    function csincRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;

        // If condition is true: dest = src1
        // If condition is false: dest = src2 + 1
        if (checkNZCVFlag(ctx)) {
            globalState.regs.spread(dest, src1);
        } else {
            globalState.regs.spread(dest, src2);
        }
    }

    if (
        mnemonic === "cinc" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, cincRegRegCallout);
    }

    function cincRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;

        // CINC is conditional increment: if condition true, dest = src + 1; else dest = src
        // For taint analysis, we propagate taint from source to destination
        globalState.regs.spread(dest, src);
    }

    return null;
}

export { handleConditionalDataProcessing };
