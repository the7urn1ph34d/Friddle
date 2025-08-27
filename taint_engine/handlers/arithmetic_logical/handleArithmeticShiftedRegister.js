import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseVector,
    globalState,
    assert
} from '../../utils.js';

/*
5.4.1 Arithmetic (shifted register)
*/
function handleArithmeticShiftedRegister(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    // let ins_list = [
    //     {
    //         mnemonic: "neg",
    //         operands: ["reg", "reg"],
    //         callout: negRegRegCallout,
    //     },
    //     {
    //         mnemonic: "sub",
    //         operands: ["reg", "reg", "reg"],
    //         callout: subRegRegRegCallout,
    //     },
    //     {
    //         mnemonic: "subs",
    //         operands: ["reg", "reg", "reg"],
    //         callout: subRegRegRegCallout,
    //     },
    //     {
    //         mnemonic: "add",
    //         operands: ["reg", "reg", "reg"],
    //         callout: addRegRegRegCallout,
    //     },
    // ];

    if (
        mnemonic === "neg" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, negRegRegCallout);
    }

    if (
        mnemonic === "sub" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: sub 3 reg_v reg_v reg_v
        return iteratorPutCalloutWrapper(instr, iterator, subRegRegRegCallout, subSIMDCallout);
    }

    if (
        mnemonic === "subs" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, subsRegRegRegCallout);
    }

    if (
        mnemonic === "add" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: add 3 reg_v reg_v reg_v
        return iteratorPutCalloutWrapper(instr, iterator, addRegRegRegCallout, addRegRegRegCallout); // FIXME: for SIMD, maybe we should write a SIMD version of this?
    }

    if (
        mnemonic === "adds" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, addsRegRegRegCallout);
    }

    if (
        mnemonic === "adcs" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, adcsRegRegRegCallout);
    }

    function addRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let op2 = parseRegOperand(ctx, operands[2]).name;

        // FIXME: we union two register based on bitmap, but why not based on reg? i mean we can write union function in register.js
        let bitmapOp1 = globalState.regs.getBitMap(op1);
        let bitmapOp2 = globalState.regs.getBitMap(op2);

        globalState.regs.fromBitMap(op0, bitmapOp1.union(bitmapOp2));
    }

    function addsRegRegRegCallout(ctx) {
        // add with flags - integer arithmetic extension - same taint logic as ADD but sets condition flags
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let op2 = parseRegOperand(ctx, operands[2]).name;

        // ADDS: add with flags，tainttaint propagation same as ADD
        let bitmapOp1 = globalState.regs.getBitMap(op1);
        let bitmapOp2 = globalState.regs.getBitMap(op2);

        globalState.regs.fromBitMap(op0, bitmapOp1.union(bitmapOp2));
    }

    function adcsRegRegRegCallout(ctx) {
        // add with carry - integer arithmetic extension - multi-source taint merge(including carry flag)
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let op2 = parseRegOperand(ctx, operands[2]).name;

        // ADCS: add with carry，dest = src1 + src2 + carry
        // need to consider three taint sources：src1, src2, and carry flag(nzcvregister)
        let bitmapOp1 = globalState.regs.getBitMap(op1);
        let bitmapOp2 = globalState.regs.getBitMap(op2);
        let carryTainted = globalState.regs.isTainted('nzcv');
        
        // merge all three source taint states
        let resultBitmap = bitmapOp1.union(bitmapOp2);
        
        if (carryTainted) {
            // if carry flag is tainted, target register must be fully tainted
            globalState.regs.taint(op0);
        } else {
            // otherwise use merged result of two register sources
            globalState.regs.fromBitMap(op0, resultBitmap);
        }
    }

    function subRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let op2 = parseRegOperand(ctx, operands[2]).name;

        let bitmapOp1 = globalState.regs.getBitMap(op1);
        let bitmapOp2 = globalState.regs.getBitMap(op2);

        globalState.regs.fromBitMap(op0, bitmapOp1.union(bitmapOp2));
    }

    // vector integer operation - subvector subtraction
    function subSIMDCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]);
        let src1 = parseRegOperand(ctx, operands[1]);
        let src2 = parseRegOperand(ctx, operands[2]);

        // vector subtraction：supportvector-vector operation
        assert(ctx, dest.vas, "dest should be SIMD register");
        assert(ctx, src1.vas, "src1 should be SIMD register");
        assert(ctx, src2.vas, "src2 should be SIMD register");

        let bitmap1 = globalState.regs.getBitMap(src1.name);
        let bitmap2 = globalState.regs.getBitMap(src2.name);

        // merge taint and propagate to target vector
        globalState.regs.fromBitMap(dest.name, bitmap1.union(bitmap2));
    }

    function subsRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let op2 = parseRegOperand(ctx, operands[2]).name;

        // SUBS: Subtract and set flags - same taint propagation as SUB
        let bitmapOp1 = globalState.regs.getBitMap(op1);
        let bitmapOp2 = globalState.regs.getBitMap(op2);

        globalState.regs.fromBitMap(op0, bitmapOp1.union(bitmapOp2));
    }

    function negRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;

        globalState.regs.spread(op0, op1);
    }

    // for (let ins of ins_list) {
    //     if (mnemonic === ins.mnemonic) {
    //         if (operands.length === ins.operands.length) {
    //             let doHandle = true;
    //             for (let i = 0; i < operands.length; i++) {
    //                 if (operands[i].type !== ins.operands[i]) {
    //                     doHandle = false;
    //                     break;
    //                 }
    //             }
    //             if (doHandle) {
    //                 return iteratorPutCalloutWrapper(
    //                     instr,
    //                     iterator,
    //                     ins.callout
    //                 );
    //             }
    //         }
    //     }
    // }

    return null;
}

export { handleArithmeticShiftedRegister };
