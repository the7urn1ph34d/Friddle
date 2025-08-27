import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseImmOperand,
    globalState
} from '../../utils.js';

/*
5.3.4 Address Generation
*/
function handleAddressGeneration(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "adr" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, adrRegImmCallout);
    }

    if (
        mnemonic === "adrp" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, adrpRegImmCallout);
    }

    function adrpRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let { immVal: immVal, shift: shift } = parseImmOperand(
            ctx,
            operands[1]
        );
        globalState.regs.untaint(dest);
    }

    function adrRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let { immVal: immVal, shift: shift } = parseImmOperand(
            ctx,
            operands[1]
        );
        globalState.regs.untaint(dest);
    }

    return null;
}

export { handleAddressGeneration };
