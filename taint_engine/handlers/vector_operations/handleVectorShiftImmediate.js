import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseImmOperand,
    parseVector,
    globalState,
    assert
} from '../../utils.js';

/*
5.7.14 Vector Shift (immediate)
*/
function handleVectorShiftImmediate(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "shl" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm"
    ) {
        // SUPPORTED_SIMD_PATTERN: shl 3 reg_v reg_v imm
        return iteratorPutCalloutWrapper(instr, iterator, null, shlRegRegImmCallout);
    }

    function shlRegRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;
        
        let destReg = parseRegOperand(ctx, operands[0]);
        let srcReg = parseRegOperand(ctx, operands[1]);
        
        assert(ctx, destReg.vas, "Destination should be a SIMD register");
        assert(ctx, srcReg.vas, "Source should be a SIMD register");
        
        let { lanes, elementBytes } = parseVector(ctx, srcReg);
        
        // Process each lane independently
        for (let i = 0; i < lanes; i++) {
            let offset = i * elementBytes;
            
            // Check if this lane is tainted in source
            if (globalState.regs.isTaintedWithOffsetAndSize(srcReg.name, offset, elementBytes)) {
                // Taint the entire destination lane
                globalState.regs.taintWithOffsetAndSize(destReg.name, offset, elementBytes);
            } else {
                // Otherwise make sure it's untainted
                globalState.regs.untaintWithOffsetAndSize(destReg.name, offset, elementBytes);
            }
        }
    }
    return null;
}

export { handleVectorShiftImmediate };
