import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    globalState, 
    assert
} from '../../utils.js';

/*
5.7.4 Vector Arithmetic
*/
function handleVectorArithmetic(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    // we comment eor out because we support eor SIMD in same way as normal register
    // if (
    //     mnemonic === "eor" &&
    //     operands.length === 3 &&
    //     operands[0].type === "reg" &&
    //     operands[1].type === "reg" &&
    //     operands[2].type === "reg"
    // ) {
    //     return iteratorPutCalloutWrapper(instr, iterator, null, eorRegRegRegCallout);
    // }

    // function eorRegRegRegCallout(ctx) {
    //     if (!globalState.letsgo) return;
    //     let instr = Instruction.parse(ctx.pc);
    //     let operands = instr.operands;

    //     let op0 = parseRegOperand(ctx, operands[0]);
    //     let op1 = parseRegOperand(ctx, operands[1]);
    //     let op2 = parseRegOperand(ctx, operands[2]);

    //     assert(ctx, op0.vas, "op0 should be SIMD register");
    //     assert(ctx, op1.vas, "op1 should be SIMD register");
    //     assert(ctx, op2.vas, "op2 should be SIMD register");

    //     let op0Vas = parseVector(ctx, op0);
    //     let op1Vas = parseVector(ctx, op1);
    //     let op2Vas = parseVector(ctx, op2);

    // }

    return null;
}

export { handleVectorArithmetic };
