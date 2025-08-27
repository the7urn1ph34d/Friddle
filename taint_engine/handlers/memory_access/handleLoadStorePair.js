import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseMemOperand,
    parseImmOperand,
    globalState,
    taintSIMDRegFromMem,
    taintMemFromSIMDReg
} from '../../utils.js';

/*
5.2.4 Load-Store Pair
*/
function handleLoadStorePair(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "ldp" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldpRegRegAddrCallout);
    }

    if (
        mnemonic === "ldp" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "mem" &&
        operands[3].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldpRegRegAddrImmCallout);
    }

    if (
        mnemonic === "stp" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, stpRegRegAddrCallout);
    }

    function ldpRegRegAddrImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[2]);
        let { immVal: immVal, shift: shift } = parseImmOperand(
            ctx,
            operands[3]
        );
        let sizeOp0 = globalState.regs.arch.registers[op0][1];
        let sizeOp1 = globalState.regs.arch.registers[op1][1];

        globalState.regs.fromBitMap(op0, globalState.mem.toBitMap(memAddr, sizeOp0));
        globalState.regs.fromBitMap(op1, globalState.mem.toBitMap(memAddr.add(sizeOp0), sizeOp1));
    }

    function stpRegRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[2]);

        globalState.mem.fromRanges(globalState.regs.toRanges(op0, memAddr));
        globalState.mem.fromRanges(
            globalState.regs.toRanges(op1, memAddr.add(globalState.regs.arch.registers[op0][1]))
        );
    }


    function ldpRegRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[2]);
        let sizeOp0 = globalState.regs.arch.registers[op0][1];
        let sizeOp1 = globalState.regs.arch.registers[op1][1];

        globalState.regs.fromBitMap(op0, globalState.mem.toBitMap(memAddr, sizeOp0));
        globalState.regs.fromBitMap(op1, globalState.mem.toBitMap(memAddr.add(sizeOp0), sizeOp1));
    }



    return null;
}

export { handleLoadStorePair };