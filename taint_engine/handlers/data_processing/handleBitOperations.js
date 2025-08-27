import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    globalState
} from '../../utils.js';

/*
5.4.5 Bit Operations
*/
function handleBitOperations(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "rev" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, revRegRegCallout);
    }

    if (
        mnemonic === "clz" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, clzRegRegCallout);
    }

    function clzRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;

        let bitmapOp1 = globalState.regs.getBitMap(src);

        if (globalState.regs.isTainted(src)) {
            globalState.regs.taint(dest);
        } else {
            globalState.regs.untaint(dest);
        }
    }

    function revRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;

        // FIXME: we reverse based on bitmap, but why not based on reg?
        let bitmapOp1 = globalState.regs.getBitMap(src);

        globalState.regs.fromBitMap(dest, bitmapOp1.reverse());
    }

    if (
        mnemonic === "rbit" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, rbitRegRegCallout);
    }

    function rbitRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;

        // RBIT: Reverse bits in register
        // For taint analysis, propagate taint from source to destination
        if (globalState.regs.isTainted(src)) {
            globalState.regs.taint(dest);
        } else {
            globalState.regs.untaint(dest);
        }
    }

    return null;
}

export { handleBitOperations };
