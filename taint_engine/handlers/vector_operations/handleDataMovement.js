import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    globalState, 
    assert,
    taintSIMDRegFromReg,
    parseVector
} from '../../utils.js';

/*
5.7.3 Data Movement
*/
function handleDataMovement(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "dup" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: dup 2 reg_v reg_v, dup 2 reg_v reg
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            dupRegRegCallout           // Modified SIMD callout supporting multiple patterns
        );
    }


    if (
        mnemonic === "umov" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: umov 2 reg reg_v
        return iteratorPutCalloutWrapper(instr, iterator, null, umovRegRegVCallout);
    }

    // dupinstructionmulti-pattern support - dup 2 reg_v reg_v + dup 2 reg_v reg
    function dupRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]);
        let src = parseRegOperand(ctx, operands[1]);

        assert(ctx, dest.vas, "dest should be SIMD register");
        
        // Intelligently handle two patterns:
        // 1. dup v0.16b, w1 (scalar to vector)
        // 2. dup v0.16b, v0.b[0] (vector element duplication)
        // taintSIMDRegFromRegfunction can correctly handle both cases
        taintSIMDRegFromReg(ctx, dest, src);
    }



    // vector-scalar conversion - umovvector element to scalar move
    function umovRegRegVCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]);
        let src = parseRegOperand(ctx, operands[1]);

        // umov w0, v0.b[0xa]: Move specific element from vector to scalar register
        assert(ctx, !dest.vas, "dest should be scalar register");
        assert(ctx, src.vectorIndex != null, "src should have vectorIndex");

        // Use API to get vector information
        let srcVector = parseVector(ctx, src);
        assert(ctx, srcVector, "src should be SIMD register");
        
        // Extract taint from specific vector element index to scalar register
        let offset = src.vectorIndex * srcVector.elementBytes;
        let srcBitMap = globalState.regs.getBitMapWithRegOffsetAndSize(src.name, offset, srcVector.elementBytes);
        globalState.regs.fromBitMap(dest.name, srcBitMap);
    }

    return null;
}

export { handleDataMovement };
