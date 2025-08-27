import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseImmOperand,
    parseVector,
    globalState, 
    assert
} from '../../utils.js';

/*
5.7.12 Vector Permute
*/
function handleVectorPermute(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "ext" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg" &&
        operands[3].type === "imm"
    ) {
        // SUPPORTED_SIMD_PATTERN: ext 4 reg_v reg_v reg_v imm
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            extRegRegRegImmCallout
        );
    }

    function extRegRegRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let destReg = parseRegOperand(ctx, operands[0]);
        let srcReg1 = parseRegOperand(ctx, operands[1]);
        let srcReg2 = parseRegOperand(ctx, operands[2]);
        let position = parseImmOperand(ctx, operands[3]).immVal;

        assert(ctx, destReg.vas, "Destination should be a SIMD register");
        assert(ctx, srcReg1.vas, "First source should be a SIMD register");
        assert(ctx, srcReg2.vas, "Second source should be a SIMD register");

        let { lanes, elementBytes } = parseVector(ctx, destReg);

        assert(ctx, lanes > position, "lanes should be greater than position");

        // Copy taint from first register (bytes from position to end)
        for (let i = 0; i < lanes - position; i++) {
            let srcOffset = position + i;
            let destOffset = i;

            // Copy taint bit by bit from srcReg1[srcOffset] to destReg[destOffset]
            let bitmap = globalState.regs.getBitMapWithRegOffsetAndSize(
                srcReg1.name,
                srcOffset,
                1
            );
            globalState.regs.setBitMapWithRegOffset(destReg.name, destOffset, bitmap);
        }

        // Copy taint from second register (bytes from start to position)
        for (let i = 0; i < position; i++) {
            let srcOffset = i;
            let destOffset = lanes - position + i;

            // Copy taint bit by bit from srcReg2[srcOffset] to destReg[destOffset]
            let bitmap = globalState.regs.getBitMapWithRegOffsetAndSize(
                srcReg2.name,
                srcOffset,
                1
            );
            globalState.regs.setBitMapWithRegOffset(destReg.name, destOffset, bitmap);
        }
    }

    if (
        mnemonic === "movi" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "imm"
    ) {
        // SUPPORTED_SIMD_PATTERN: movi 2 reg_v imm
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            moviRegImmCallout,
            moviRegImmCallout
        );
    }

    function moviRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]);
        let { immVal: immVal } = parseImmOperand(ctx, operands[1]);

        globalState.regs.untaint(dest.name);
    }

    return null;
}

export { handleVectorPermute };
