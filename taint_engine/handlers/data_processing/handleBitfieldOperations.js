import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseImmOperand,
    globalState
} from '../../utils.js';

/*
5.3.5 Bitfield Operations
*/
function handleBitfieldOperations(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    //TODO: instead of using if check for each instruction, we can make template like {'ubfx': {operands: [reg, reg, imm, imm], callout: ubfxRegRegImmImmCallout}}. so we avoid for loop to match the instruction. tracing callout registeration status need to be updated to support this.

    // NO, we can't easily using {'ins' : {}}. we should use {'ins': [{}, {}]}
    // because for ins, we might have different operands, and different callout function

    // and think about to organize them into class way, so we can easily add new instruction and callout function

    // TODO: except todo and fixme, do we have other comment type? and does vscode extension support it? if not find a new one, if yes how do we configure it.
    if (
        mnemonic === "ubfx" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm" &&
        operands[3].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            ubfxRegRegImmImmCallout
        );
    }

    if (
        mnemonic === "bfi" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm" &&
        operands[3].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, bfiRegRegImmImmCallout);
    }

    if (
        mnemonic === "bfxil" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm" &&
        operands[3].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, bfxilRegRegImmImmCallout);
    }

    if (
        mnemonic === "sbfiz" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm" &&
        operands[3].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, sbfizRegRegImmImmCallout);
    }

    if (
        mnemonic === "ubfiz" &&
        operands.length === 4 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "imm" &&
        operands[3].type === "imm"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ubfizRegRegImmImmCallout);
    }

    // FIXME: we easily spread tainted register to destination register right now. we should check range of the source register and only spread the range that is in the bitfield range
    function ubfxRegRegImmImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let { immVal: immVal1, shift: shift1 } = parseImmOperand(
            ctx,
            operands[2]
        );
        let { immVal: immVal2, shift: shift2 } = parseImmOperand(
            ctx,
            operands[3]
        );
        globalState.regs.spread(op0, op1);
    }

    function bfiRegRegImmImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;
        let { immVal: lsb } = parseImmOperand(ctx, operands[2]);  // LSB position in destination
        let { immVal: width } = parseImmOperand(ctx, operands[3]); // Width of field

        // BFI: Insert src[width-1:0] into dest[lsb+width-1:lsb]
        // Example: bfi x9, x12, #32, #32
        //   x9 = (x9 & ~(0xFFFFFFFFULL << 32)) | ((x12 & 0xFFFFFFFFULL) << 32)
        //   Preserves other bits of destination
        
        // Check if source's low bits are tainted (the bits being inserted)
        let srcLowByteCount = Math.ceil(width / 8);
        let srcFieldTainted = globalState.regs.isTaintedWithOffsetAndSize(src, 0, srcLowByteCount);

        // Calculate which bytes in destination will be affected
        let destStartByte = Math.floor(lsb / 8);
        let destEndByte = Math.floor((lsb + width - 1) / 8);
        let destByteCount = destEndByte - destStartByte + 1;

        if (srcFieldTainted) {
            // Taint the affected bytes in destination
            globalState.regs.taintWithOffsetAndSize(dest, destStartByte, destByteCount);
        } else {
            // Clear taint in the affected bytes only (preserve other bytes)
            globalState.regs.untaintWithOffsetAndSize(dest, destStartByte, destByteCount);
        }
    }

    function bfxilRegRegImmImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;
        let { immVal: lsb } = parseImmOperand(ctx, operands[2]);   // LSB position in source
        let { immVal: width } = parseImmOperand(ctx, operands[3]); // Width of field

        // BFXIL: Extract src[lsb+width-1:lsb] and insert into dest[width-1:0]
        // Example: bfxil x9, x1, #8, #6
        //   field = (x1 >> 8) & 0x3F;  // extract x1[13:8]
        //   x9 = field;                // write to x9[5:0], clear upper bits
        // IMPORTANT: Destination's upper bits are CLEARED, not preserved!
        
        // Calculate which bytes in source field are affected
        let srcStartByte = Math.floor(lsb / 8);
        let srcEndByte = Math.floor((lsb + width - 1) / 8);
        let srcByteCount = srcEndByte - srcStartByte + 1;
        
        // Check if the source field is tainted using the proper API
        let srcFieldTainted = globalState.regs.isTaintedWithOffsetAndSize(src, srcStartByte, srcByteCount);

        // BFXIL clears the entire destination register, then sets the lower bits
        globalState.regs.untaint(dest);

        if (srcFieldTainted) {
            // Calculate destination bytes (lower bits that will be set)
            let destByteCount = Math.ceil(width / 8);
            
            // Taint the lower bytes of destination
            globalState.regs.taintWithOffsetAndSize(dest, 0, destByteCount);
        }
        // If source field is not tainted, destination remains clean (already cleared above)
    }

    // signed bitfield insert and zero - integer arithmetic extension - single source taint propagation
    function sbfizRegRegImmImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;
        // Immediate parameters do not affect taint propagation, no parsing needed

        // SBFIZ: Signed bitfield insert and zero
        // dest = (src << lsb) & mask，then sign extend
        // simplified to single source taint propagation because all output bits depend on source register
        globalState.regs.spread(dest, src);
    }

    // unsigned bitfield insert and zero - integer arithmetic extension - single source taint propagation
    function ubfizRegRegImmImmCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;
        // Immediate parameters do not affect taint propagation, no parsing needed

        // UBFIZ: unsigned bitfield insert and zero
        // dest = (src << lsb) & mask
        // simplified to single source taint propagation because all output bits depend on source register
        globalState.regs.spread(dest, src);
    }

    return null;
}

export { handleBitfieldOperations };
