import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseMemOperand,
    globalState
} from '../../utils.js';

/*
5.6.1 Floating-point/SIMD Scalar Memory Access
*/
function handleFloatingPointSIMDScalarMemoryAccess(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "stp" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "mem" &&
        operands[3].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            stpRegRegAddrImmCallout
        );
    }

    function stpRegRegAddrImmCallout(ctx) {
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

    return null;
}

export { handleFloatingPointSIMDScalarMemoryAccess };
