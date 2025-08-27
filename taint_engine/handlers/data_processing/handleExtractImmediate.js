import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand,
    parseImmOperand,
    globalState
} from '../../utils.js';

/*
5.3.6 Extract (immediate)
*/
function handleExtractImmediate(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    if (
        mnemonic === "extr" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg" &&
        operands[3].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, extrRegRegRegImmCallout);
    }

    // extract register - integer arithmetic extension - multi-source taint merge
    function extrRegRegRegImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src1 = parseRegOperand(ctx, operands[1]).name;  // high source
        let src2 = parseRegOperand(ctx, operands[2]).name;  // low source
        // Immediate parameters do not affect taint propagation, no parsing needed

        // EXTR: extract bits from concatenated two registers
        // dest = (src1 || src2) >> lsb
        // result may depend on two source registers, using multi-source taint merge
        let bitmapSrc1 = globalState.regs.getBitMap(src1);
        let bitmapSrc2 = globalState.regs.getBitMap(src2);

        globalState.regs.fromBitMap(dest, bitmapSrc1.union(bitmapSrc2));
    }

    return null;
}

export { handleExtractImmediate };
