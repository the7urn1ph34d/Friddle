import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    globalState
} from '../../utils.js';

/*
5.6.2 Floating-point Move (register)
*/
function handleFloatingPointMoveRegister(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "fmov" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, fmovRegRegCallout);
    }

    // floating point register move instruction implementation
    function fmovRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;

        // floating point move：target register inherits source register taint
        globalState.regs.spread(dest, src);
    }

    return null;
}

export { handleFloatingPointMoveRegister };
