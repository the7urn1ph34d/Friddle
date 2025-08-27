import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseMemOperand,
    globalState, 
    assert,
    taintSIMDRegFromMem,
    taintMemFromSIMDReg
} from '../../utils.js';

/*
5.7.22 Vector Load-Store Structure
*/
function handleVectorLoadStoreStructure(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "ld1" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem" &&
        operands[2].type === "imm"
    ) {
        // SUPPORTED_SIMD_PATTERN: ld1 3 reg_v mem imm
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            ld1RegMemImmCallout
        );
    }

    function ld1RegMemImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]);
        let op1 = parseMemOperand(ctx, operands[1]);

        taintSIMDRegFromMem(ctx, op0, op1.memAddr);
    }

    if (
        mnemonic === "ld1" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        // SUPPORTED_SIMD_PATTERN: ld1 2 reg_v mem
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            ld1RegMemCallout
        );
    }

    function ld1RegMemCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]);
        let op1 = parseMemOperand(ctx, operands[1]);

        taintSIMDRegFromMem(ctx, op0, op1.memAddr);
    }

    if (
        mnemonic === "ld1" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem" &&
        operands[2].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: ld1 3 reg_v mem reg
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            ld1RegMemCallout // we just use ld1RegMemCallout here, because we dont care about post-indexed addressing here.
        );
    }



    if (
        mnemonic === "ld1" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "mem" &&
        operands[3].type === "imm"
    ) {
        // SUPPORTED_SIMD_PATTERN: ld1 4 reg_v reg_v mem imm
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            ld1RegRegMemCallout // we just use ld1RegRegMemImmCallout here, because we dont care about post-indexed addressing here.
        );
    }



    if (
        mnemonic === "ld1" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "mem"
    ) {
        // SUPPORTED_SIMD_PATTERN: ld1 3 reg_v reg_v mem
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            ld1RegRegMemCallout 
        );
    }

    function ld1RegRegMemCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]);
        let op1 = parseRegOperand(ctx, operands[1]);
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[2]);

        let taintedBytes = taintSIMDRegFromMem(ctx, op0, memAddr);
        taintedBytes = taintSIMDRegFromMem(ctx, op1, memAddr.add(taintedBytes));
    }

    if (
        mnemonic === "st1" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        // SUPPORTED_SIMD_PATTERN: st1 2 reg_v mem
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            st1RegMemCallout
        );
    }

    function st1RegMemCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]);
        let op1 = parseMemOperand(ctx, operands[1]);

        taintMemFromSIMDReg(ctx, op1.memAddr, op0);
    }

    if (
        mnemonic === "ld1r" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        // SUPPORTED_SIMD_PATTERN: ld1r 2 reg_v mem
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            ld1rRegMemCallout
        );
    }

    function ld1rRegMemCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let destReg = parseRegOperand(ctx, operands[0]);
        let memOp = parseMemOperand(ctx, operands[1]);

        // ld1r: load single element from memory, replicate to all lanes of vector register
        let {elementBytes} = parseVector(ctx, destReg);
        
        // only load memory size of single element
        let elementBitMap = globalState.mem.toBitMap(memOp.memAddr, elementBytes);
        
        // if source element is tainted, taint all lanes
        if (!elementBitMap.isEmpty()) {
            // get vector info and set all lanes
            let {lanes} = parseVector(ctx, destReg);
            for (let i = 0; i < lanes; i++) {
                let offset = i * elementBytes;
                globalState.regs.setBitMapWithRegOffset(destReg.name, offset, elementBitMap);
            }
        } else {
            // clear entire vector register
            globalState.regs.untaint(destReg.name);
        }
    }

    if (
        mnemonic === "ld2" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "mem"
    ) {
        // SUPPORTED_SIMD_PATTERN: ld2 3 reg_v reg_v mem
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            ld2RegRegMemCallout
        );
    }

    function ld2RegRegMemCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let destReg0 = parseRegOperand(ctx, operands[0]);
        let destReg1 = parseRegOperand(ctx, operands[1]);
        let memOp = parseMemOperand(ctx, operands[2]);

        // ld2: load interleaved dual element structure from memory to two vector registers
        // load first vector register
        let bytesRead = taintSIMDRegFromMem(ctx, destReg0, memOp.memAddr);
        // load second vector register from consecutive address
        taintSIMDRegFromMem(ctx, destReg1, memOp.memAddr.add(bytesRead));
    }

    if (
        mnemonic === "st2" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "mem"
    ) {
        // SUPPORTED_SIMD_PATTERN: st2 3 reg_v reg_v mem
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            st2RegRegMemCallout
        );
    }

    function st2RegRegMemCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let srcReg0 = parseRegOperand(ctx, operands[0]);
        let srcReg1 = parseRegOperand(ctx, operands[1]);
        let memOp = parseMemOperand(ctx, operands[2]);

        // st2: store two vector registers to memory in interleaved manner
        let bytesWritten = taintMemFromSIMDReg(ctx, memOp.memAddr, srcReg0);
        taintMemFromSIMDReg(ctx, memOp.memAddr.add(bytesWritten), srcReg1);
    }

    if (
        mnemonic === "st3" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg" &&
        operands[3].type === "mem"
    ) {
        // SUPPORTED_SIMD_PATTERN: st3 4 reg_v reg_v reg_v mem
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            st3RegRegRegMemCallout
        );
    }

    function st3RegRegRegMemCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let srcReg0 = parseRegOperand(ctx, operands[0]);
        let srcReg1 = parseRegOperand(ctx, operands[1]);
        let srcReg2 = parseRegOperand(ctx, operands[2]);
        let memOp = parseMemOperand(ctx, operands[3]);

        // st3: store three vector registers to memory in interleaved manner
        let bytesWritten = taintMemFromSIMDReg(ctx, memOp.memAddr, srcReg0);
        bytesWritten += taintMemFromSIMDReg(ctx, memOp.memAddr.add(bytesWritten), srcReg1);
        taintMemFromSIMDReg(ctx, memOp.memAddr.add(bytesWritten), srcReg2);
    }

    if (
        mnemonic === "st4" &&
        operands.length === 5 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg" &&
        operands[3].type === "reg" &&
        operands[4].type === "mem"
    ) {
        // SUPPORTED_SIMD_PATTERN: st4 5 reg_v reg_v reg_v reg_v mem
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            st4RegRegRegRegMemCallout
        );
    }

    function st4RegRegRegRegMemCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let srcReg0 = parseRegOperand(ctx, operands[0]);
        let srcReg1 = parseRegOperand(ctx, operands[1]);
        let srcReg2 = parseRegOperand(ctx, operands[2]);
        let srcReg3 = parseRegOperand(ctx, operands[3]);
        let memOp = parseMemOperand(ctx, operands[4]);

        // st4: store four vector registers to memory in interleaved manner
        let bytesWritten = taintMemFromSIMDReg(ctx, memOp.memAddr, srcReg0);
        bytesWritten += taintMemFromSIMDReg(ctx, memOp.memAddr.add(bytesWritten), srcReg1);
        bytesWritten += taintMemFromSIMDReg(ctx, memOp.memAddr.add(bytesWritten), srcReg2);
        taintMemFromSIMDReg(ctx, memOp.memAddr.add(bytesWritten), srcReg3);
    }

    if (
        mnemonic === "ld4" &&
        operands.length === 5 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg" &&
        operands[3].type === "reg" &&
        operands[4].type === "mem"
    ) {
        // SUPPORTED_SIMD_PATTERN: ld4 5 reg_v reg_v reg_v reg_v mem
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            ld4RegRegRegRegMemCallout
        );
    }

    function ld4RegRegRegRegMemCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let destReg0 = parseRegOperand(ctx, operands[0]);
        let destReg1 = parseRegOperand(ctx, operands[1]);
        let destReg2 = parseRegOperand(ctx, operands[2]);
        let destReg3 = parseRegOperand(ctx, operands[3]);
        let memOp = parseMemOperand(ctx, operands[4]);

        // ld4: load interleaved quad element structure from memory to four vector registers
        let bytesRead = taintSIMDRegFromMem(ctx, destReg0, memOp.memAddr);
        bytesRead += taintSIMDRegFromMem(ctx, destReg1, memOp.memAddr.add(bytesRead));
        bytesRead += taintSIMDRegFromMem(ctx, destReg2, memOp.memAddr.add(bytesRead));
        taintSIMDRegFromMem(ctx, destReg3, memOp.memAddr.add(bytesRead));
    }

    if (
        mnemonic === "ld1" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem" &&
        operands[2].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: ld1 3 reg_v mem reg
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            ld1RegMemRegCallout
        );
    }

    function ld1RegMemRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let destReg = parseRegOperand(ctx, operands[0]);
        let memOp = parseMemOperand(ctx, operands[1]);

        // ld1 with register offset: load from memory to vector register, ignore register offset calculation
        taintSIMDRegFromMem(ctx, destReg, memOp.memAddr);
    }




    return null;
}

export { handleVectorLoadStoreStructure };
