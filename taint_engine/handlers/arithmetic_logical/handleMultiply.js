import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseVector,
    globalState,
    assert
} from '../../utils.js';

/*
5.5.1 Multiply
*/
function handleMultiply(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "mul" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: mul 3 reg_v reg_v reg_v
        return iteratorPutCalloutWrapper(instr, iterator, mulRegRegRegCallout, mulSIMDCallout);
    }

    function mulRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;

        if (globalState.regs.isTainted(src1) || globalState.regs.isTainted(src2)) {
            globalState.regs.taint(dest);
        }
    }

    // vector integer operation - mulvector multiplication
    function mulSIMDCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]);
        let src1 = parseRegOperand(ctx, operands[1]);
        let src2 = parseRegOperand(ctx, operands[2]);

        // vector multiplication：supports vector-vector and vector-scalar operations
        assert(ctx, dest.vas, "dest should be SIMD register");
        assert(ctx, src1.vas, "src1 should be SIMD register");
        assert(ctx, src2.vas, "src2 should be SIMD register");

        let bitmap1 = globalState.regs.getBitMap(src1.name);
        let bitmap2;

        if (src2.vectorIndex !== null) {
            // vector-scalar operation：mul v0.2s, v0.2s, v0.s[1]
            // use API to get element info, precisely extract element taint
            let vectorInfo = parseVector(src2.vas);
            let offset = src2.vectorIndex * vectorInfo.elementBytes;
            bitmap2 = globalState.regs.getBitMapWithRegOffsetAndSize(src2.name, offset, vectorInfo.elementBytes);
        } else {
            // vector-vector operation：mul v0.2s, v0.2s, v1.2s
            bitmap2 = globalState.regs.getBitMap(src2.name);
        }

        // merge taint and propagate to target vector
        globalState.regs.fromBitMap(dest.name, bitmap1.union(bitmap2));
    }

    if (
        mnemonic === "umulh" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, umulhRegRegRegCallout);
    }

    function umulhRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;

        if (globalState.regs.isTainted(src1) || globalState.regs.isTainted(src2)) {
            globalState.regs.taint(dest);
        } else {
            globalState.regs.untaint(dest);
        }
    }

    if (
        mnemonic === "msub" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg" &&
        operands[3].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, msubRegRegRegRegCallout);
    }

    function msubRegRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;
        let src3 = parseRegOperand(ctx, operands[3]).name;

        if (globalState.regs.isTainted(src1) || globalState.regs.isTainted(src2) || globalState.regs.isTainted(src3)) {
            globalState.regs.taint(dest);
        } else {
            globalState.regs.untaint(dest);
        }
    }    

    if (
        mnemonic === "madd" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg" &&
        operands[3].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, maddRegRegRegRegCallout);
    }

    if (
        mnemonic === "smaddl" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg" &&
        operands[3].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, smaddlRegRegRegRegCallout);
    }

    if (
        mnemonic === "umaddl" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg" &&
        operands[3].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, umaddlRegRegRegRegCallout);
    }

    if (
        mnemonic === "umull" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, umullRegRegRegCallout);
    }    

    function maddRegRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;
        let src3 = parseRegOperand(ctx, operands[3]).name;

        // MADD: dest = src3 + (src1 * src2)
        if (globalState.regs.isTainted(src1) || globalState.regs.isTainted(src2) || globalState.regs.isTainted(src3)) {
            globalState.regs.taint(dest);
        } else {
            globalState.regs.untaint(dest);
        }
    }

    function smaddlRegRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;
        let src3 = parseRegOperand(ctx, operands[3]).name;

        // SMADDL: Signed multiply-add long (32x32->64)
        if (globalState.regs.isTainted(src1) || globalState.regs.isTainted(src2) || globalState.regs.isTainted(src3)) {
            globalState.regs.taint(dest);
        } else {
            globalState.regs.untaint(dest);
        }
    }

    function umaddlRegRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;
        let src3 = parseRegOperand(ctx, operands[3]).name;

        // UMADDL: Unsigned multiply-add long (32x32->64)
        if (globalState.regs.isTainted(src1) || globalState.regs.isTainted(src2) || globalState.regs.isTainted(src3)) {
            globalState.regs.taint(dest);
        } else {
            globalState.regs.untaint(dest);
        }
    }

    function umullRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;

        // UMULL: Unsigned multiply long (32x32->64)
        if (globalState.regs.isTainted(src1) || globalState.regs.isTainted(src2)) {
            globalState.regs.taint(dest);
        } else {
            globalState.regs.untaint(dest);
        }
    }

    if (
        mnemonic === "mneg" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, mnegRegRegRegCallout);
    }

    function mnegRegRegRegCallout(ctx) {
        // multiply negate - integer arithmetic extension - multi-source taint merge(multiplication operation)
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;

        // MNEG: multiply negate，dest = -(src1 * src2)，multi-source taint merge
        let bitmapOp1 = globalState.regs.getBitMap(src1);
        let bitmapOp2 = globalState.regs.getBitMap(src2);

        globalState.regs.fromBitMap(dest, bitmapOp1.union(bitmapOp2));
    }

    return null;
}

export { handleMultiply };
