import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseVector,
    globalState,
    taintSIMDRegFromReg,
    assert
} from '../../utils.js';

/*
5.6.7 Floating-point Arithmetic (2 source)
*/
function handleFloatingPointArithmetic2Source(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "fmul" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: fmul 3 reg_v reg_v reg_v
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            fmulRegRegRegCallout,
            fmulSIMDCallout
        );
    }

    if (
        mnemonic === "fadd" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: fadd 3 reg_v reg_v reg_v
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            faddRegRegRegCallout,
            faddSIMDCallout
        );
    }

    if (
        mnemonic === "fsub" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: fsub 3 reg_v reg_v reg_v
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            fsubRegRegRegCallout,
            fsubSIMDCallout
        );
    }

    if (
        mnemonic === "fdiv" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, fdivRegRegRegCallout);
    }

    function fmulRegRegRegCallout(ctx) {
        // floating point multiplicationinstructionimplementation
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;

        // floating point multiplication：target register inherits source register taint
        let bitmap1 = globalState.regs.getBitMap(src1);
        let bitmap2 = globalState.regs.getBitMap(src2);
        globalState.regs.fromBitMap(dest, bitmap1.union(bitmap2));
    }

    function faddRegRegRegCallout(ctx) {
        // floating point additioninstructionimplementation
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;

        // floating point addition：target register inherits source register taint
        let bitmap1 = globalState.regs.getBitMap(src1);
        let bitmap2 = globalState.regs.getBitMap(src2);
        globalState.regs.fromBitMap(dest, bitmap1.union(bitmap2));
    }

    function fsubRegRegRegCallout(ctx) {
        // floating point subtractioninstructionimplementation
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;

        // floating point subtraction：target register inherits source register taint
        let bitmap1 = globalState.regs.getBitMap(src1);
        let bitmap2 = globalState.regs.getBitMap(src2);
        globalState.regs.fromBitMap(dest, bitmap1.union(bitmap2));
    }

    function fdivRegRegRegCallout(ctx) {
        // floating point divisioninstructionimplementation
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;
        let src2 = parseRegOperand(ctx, operands[2]).name;

        // floating point division：target register inherits source register taint
        let bitmap1 = globalState.regs.getBitMap(src1);
        let bitmap2 = globalState.regs.getBitMap(src2);
        globalState.regs.fromBitMap(dest, bitmap1.union(bitmap2));
    }

    // vector floating point operation - fmulvector floating point multiplication
    function fmulSIMDCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]);
        let src1 = parseRegOperand(ctx, operands[1]);
        let src2 = parseRegOperand(ctx, operands[2]);

        // vector floating point multiplication：supports vector-vector and vector-scalar operations
        assert(ctx, dest.vas, "dest should be SIMD register");
        assert(ctx, src1.vas, "src1 should be SIMD register");
        assert(ctx, src2.vas, "src2 should be SIMD register");

        let bitmap1 = globalState.regs.getBitMap(src1.name);
        let bitmap2;

        if (src2.vectorIndex !== null) {
            // vector-scalar operation：fmul v0.2d, v0.2d, v1.d[0]
            // use API to get element info, precisely extract element taint
            let vectorInfo = parseVector(src2.vas);
            let offset = src2.vectorIndex * vectorInfo.elementBytes;
            bitmap2 = globalState.regs.getBitMapWithRegOffsetAndSize(src2.name, offset, vectorInfo.elementBytes);
        } else {
            // vector-vector operation：fmul v0.2d, v0.2d, v1.2d
            bitmap2 = globalState.regs.getBitMap(src2.name);
        }

        // merge taint and propagate to target vector
        globalState.regs.fromBitMap(dest.name, bitmap1.union(bitmap2));
    }

    // vector floating point operation - faddvector floating point addition
    function faddSIMDCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]);
        let src1 = parseRegOperand(ctx, operands[1]);
        let src2 = parseRegOperand(ctx, operands[2]);

        // vector floating point addition：supports vector-vector and vector-scalar operations
        assert(ctx, dest.vas, "dest should be SIMD register");
        assert(ctx, src1.vas, "src1 should be SIMD register");
        assert(ctx, src2.vas, "src2 should be SIMD register");

        let bitmap1 = globalState.regs.getBitMap(src1.name);
        let bitmap2;

        if (src2.vectorIndex !== null) {
            // vector-scalar operation：fadd v0.2d, v0.2d, v1.d[0]
            let vectorInfo = parseVector(src2.vas);
            let offset = src2.vectorIndex * vectorInfo.elementBytes;
            bitmap2 = globalState.regs.getBitMapWithRegOffsetAndSize(src2.name, offset, vectorInfo.elementBytes);
        } else {
            // vector-vector operation：fadd v0.2d, v0.2d, v1.2d
            bitmap2 = globalState.regs.getBitMap(src2.name);
        }

        globalState.regs.fromBitMap(dest.name, bitmap1.union(bitmap2));
    }

    // vector floating point operation - fsubvector floating point subtraction
    function fsubSIMDCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]);
        let src1 = parseRegOperand(ctx, operands[1]);
        let src2 = parseRegOperand(ctx, operands[2]);

        // vector floating point subtraction：supports vector-vector and vector-scalar operations
        assert(ctx, dest.vas, "dest should be SIMD register");
        assert(ctx, src1.vas, "src1 should be SIMD register");
        assert(ctx, src2.vas, "src2 should be SIMD register");

        let bitmap1 = globalState.regs.getBitMap(src1.name);
        let bitmap2;

        if (src2.vectorIndex !== null) {
            // vector-scalar operation：fsub v0.2d, v0.2d, v1.d[0]
            let vectorInfo = parseVector(src2.vas);
            let offset = src2.vectorIndex * vectorInfo.elementBytes;
            bitmap2 = globalState.regs.getBitMapWithRegOffsetAndSize(src2.name, offset, vectorInfo.elementBytes);
        } else {
            // vector-vector operation：fsub v0.2d, v0.2d, v1.2d
            bitmap2 = globalState.regs.getBitMap(src2.name);
        }

        globalState.regs.fromBitMap(dest.name, bitmap1.union(bitmap2));
    }

    return null;
}

export { handleFloatingPointArithmetic2Source };
