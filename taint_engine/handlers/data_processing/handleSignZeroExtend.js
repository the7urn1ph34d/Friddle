import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand,
    globalState
} from '../../utils.js';

/*
5.3.8 Sign/Zero Extend
*/
function handleSignZeroExtend(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "sxth" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, sxthRegRegCallout);
    }

    // sign extend halfword - integer arithmetic extension - single source taint propagation
    function sxthRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;

        // SXTH: sign extend halfword，sign extend low bits from source to dest
        // output completely depends on input, use single source taint propagation
        globalState.regs.spread(dest, src);
    }

    return null;
}

export { handleSignZeroExtend };
