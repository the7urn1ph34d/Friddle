import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseImmOperand,
    globalState, 
    assert,
    parseVector,
    colorLog
} from '../../utils.js';

/*
5.3.1 Arithmetic (immediate)
*/
function handleArithmeticImmediate(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "add" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, addRegRegImmCallout);
    }

    if (
        mnemonic === "adds" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, addRegRegImmCallout);
    }

    if (
        mnemonic === "sub" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, subRegRegImmCallout);
    }

    if (
        mnemonic === "subs" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, subRegRegImmCallout);
    }

    if (
        mnemonic === "mov" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: mov 2 reg reg_v, mov 2 reg_v reg_v
        return iteratorPutCalloutWrapper(instr, iterator, movRegRegCallout, movRegRegSIMDCallout);
    }

    function movRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        globalState.regs.spread(op0, op1);
    }

    // movmulti-pattern support - mov 2 reg reg_v + mov 2 reg_v reg_v
    function movRegRegSIMDCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]);
        let src = parseRegOperand(ctx, operands[1]);

        // TODO: compilation stage should distinguish different patterns to avoid runtime judgment
        // Pattern 1: mov 2 reg_v reg_v - complete vector-to-vector move
        // Pattern 2: mov 2 reg reg_v - vector element to scalar move
        
        if (dest.vas && src.vas) {
            // mov v0.16b, v1.16b - complete vector-to-vector move
            globalState.regs.spread(dest.name, src.name);
        } else if (!dest.vas && src.vas) {
            // mov x3, v17.d[0] - vector element to scalar move
            let srcVector = parseVector(ctx, src);
            assert(ctx, srcVector, "src should be SIMD register");
            
            let offset = src.vectorIndex * srcVector.elementBytes;
            let srcBitMap = globalState.regs.getBitMapWithRegOffsetAndSize(src.name, offset, srcVector.elementBytes);
            globalState.regs.fromBitMap(dest.name, srcBitMap);
        }
        // other cases not handled, skip directly
        else {
            if (src.name.startsWith("v") && !src.vas) {
                // TODO: need to implement own operand parsing function instead of relying on provided dictionary
                colorLog("Skip mov pattern (Frida bug: v register missing vas property): " + instr.toString() + ", JSON: " + JSON.stringify(instr), "yellow");
            } else {
                colorLog("Skip unsupported mov pattern: dest.vas=" + !!dest.vas + ", src.vas=" + !!src.vas + ", instr: " + instr.toString() + ", JSON: " + JSON.stringify(instr), "yellow");
            }
        }
    }

    function subRegRegImmCallout(ctx) {
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

    function addRegRegImmCallout(ctx) {
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

    return null;
}

export { handleArithmeticImmediate };