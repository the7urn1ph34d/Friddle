import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseImmOperand,
    globalState
} from '../../utils.js';

/*
5.3.3 Move (wide immediate)
*/
function handleMoveWideImmediate(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "mov" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, movRegImmCallout);
    }

    function movRegImmCallout(ctx) {
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

    if (
        mnemonic === "movk" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, movkRegImmCallout);
    }

    function movkRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;
    
        let dest = parseRegOperand(ctx, operands[0]).name;
        let { immVal: immVal, shift: shift } = parseImmOperand(ctx, operands[1]);
        
        let shiftAmount = shift ? shift.value : 0;
        let byteOffset = shiftAmount / 8;
        let fieldSize = 2;
        
        globalState.regs.untaintWithOffsetAndSize(dest, byteOffset, fieldSize);
    }


    return null;
}

export { handleMoveWideImmediate };
