import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    globalState, 
    assert
} from '../../utils.js';

/*
5.7.24 Crypto Extension
*/
function handleCryptoExtension(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "aese" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: aese 2 reg_v reg_v
        return iteratorPutCalloutWrapper(instr, iterator, null, aeseRegRegCallout);
    }

    // AES encryption round - aeseinstruction
    function aeseRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;
        
        let destReg = parseRegOperand(ctx, operands[0]);
        let srcReg = parseRegOperand(ctx, operands[1]);
        
        assert(ctx, destReg.vas, "Destination should be a SIMD register");
        assert(ctx, srcReg.vas, "Source should be a SIMD register");

        // AESE: AES Encrypt Round - both dest and src contribute to result
        // For taint analysis: if either dest or src is tainted, result is tainted
        if (globalState.regs.isTainted(destReg.name) || globalState.regs.isTainted(srcReg.name)) {
            globalState.regs.taint(destReg.name);
        } else {
            globalState.regs.untaint(destReg.name);
        }
    }

    // AES mix columns transform - aesmcinstruction
    function aesmcRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;
        
        let destReg = parseRegOperand(ctx, operands[0]);
        let srcReg = parseRegOperand(ctx, operands[1]);
        
        assert(ctx, destReg.vas, "Destination should be a SIMD register");
        assert(ctx, srcReg.vas, "Source should be a SIMD register");

        // AESMC: AES Mix Columns - transforms source to destination
        // For taint analysis: propagate taint from source to destination
        if (globalState.regs.isTainted(srcReg.name)) {
            globalState.regs.taint(destReg.name);
        } else {
            globalState.regs.untaint(destReg.name);
        }
    }

    if (
        mnemonic === "aesmc" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: aesmc 2 reg_v reg_v
        return iteratorPutCalloutWrapper(instr, iterator, null, aesmcRegRegCallout);
    }

    if (
        mnemonic === "aesd" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: aesd 2 reg_v reg_v
        return iteratorPutCalloutWrapper(instr, iterator, null, aesdRegRegCallout);
    }

    if (
        mnemonic === "aesimc" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: aesimc 2 reg_v reg_v
        return iteratorPutCalloutWrapper(instr, iterator, null, aesimcRegRegCallout);
    }

    // AES decryption round - aesdinstruction
    function aesdRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;
        
        let destReg = parseRegOperand(ctx, operands[0]);
        let srcReg = parseRegOperand(ctx, operands[1]);
        
        assert(ctx, destReg.vas, "Destination should be a SIMD register");
        assert(ctx, srcReg.vas, "Source should be a SIMD register");

        // AESD: AES Decrypt Round - both dest and src contribute to result
        // For taint analysis: if either dest or src is tainted, result is tainted
        if (globalState.regs.isTainted(destReg.name) || globalState.regs.isTainted(srcReg.name)) {
            globalState.regs.taint(destReg.name);
        } else {
            globalState.regs.untaint(destReg.name);
        }
    }

    // AES inverse mix columns - aesimcinstruction
    function aesimcRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;
        
        let destReg = parseRegOperand(ctx, operands[0]);
        let srcReg = parseRegOperand(ctx, operands[1]);
        
        assert(ctx, destReg.vas, "Destination should be a SIMD register");
        assert(ctx, srcReg.vas, "Source should be a SIMD register");

        // AESIMC: AES Inverse Mix Columns
        // For taint analysis, propagate taint from source to destination
        if (globalState.regs.isTainted(srcReg.name)) {
            globalState.regs.taint(destReg.name);
        } else {
            globalState.regs.untaint(destReg.name);
        }
    }

    return null;
}

export { handleCryptoExtension };