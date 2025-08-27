import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseVector,
    globalState,
    assert
} from '../../utils.js';

/*
5.7.21 Vector Table Lookup
*/
function handleVectorTableLookup(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "tbl" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: tbl 3 reg_v reg_v reg_v
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            null,
            tblRegRegRegCallout
        );
    }

    function tblRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]);
        let op1 = parseRegOperand(ctx, operands[1]);
        let op2 = parseRegOperand(ctx, operands[2]);

        assert(ctx, op0.vas, "op0 should be SIMD register");
        assert(ctx, op1.vas, "op1 should be SIMD register");
        assert(ctx, op2.vas, "op2 should be SIMD register");

        let op0Vas = parseVector(ctx, op0);
        let op1Vas = parseVector(ctx, op1);
        let op2Vas = parseVector(ctx, op2);

        // ensure op2Val is arraybuffer
        assert(
            ctx,
            op2.regVal instanceof ArrayBuffer,
            "op2Val should be arraybuffer"
        );
        let op2ValUint8Array = new Uint8Array(op2.regVal);
        // since lanes could only be 8, 16 and element size is 1.

        for (let i = 0; i < op2Vas.lanes; i++) {
            // check when op2Vas[i] is tainted or op1Vas[op2Val[i]] is tainted, then we taint op0Vas[i]

            //get the value of op2 i lane
            let op2Val_i = op2ValUint8Array[i];

            if (
                globalState.regs.isTaintedWithOffsetAndSize(op2.name, i, 1) ||
                globalState.regs.isTaintedWithOffsetAndSize(op1.name, op2Val_i, 1)
            ) {
                globalState.regs.taintWithOffsetAndSize(op0.name, i, 1);
            }
        }
    }

    return null;
}

export { handleVectorTableLookup };
