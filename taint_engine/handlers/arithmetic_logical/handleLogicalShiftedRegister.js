import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    globalState
} from '../../utils.js';

/*
5.4.3 Logical (shifted register)
*/
function handleLogicalShiftedRegister(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    // let ins_list = [
    //     {
    //         mnemonic: "bic",
    //         operands: ["reg", "reg", "reg"],
    //         callout: bicRegRegRegCallout,
    //     },
    //     {
    //         mnemonic: "orr",
    //         operands: ["reg", "reg", "reg"],
    //         callout: orrRegRegRegCallout,
    //     },
    //     {
    //         mnemonic: "eor",
    //         operands: ["reg", "reg", "reg"],
    //         callout: eorRegRegRegCallout,
    //     },
    // ];

    if (
        mnemonic === "bic" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, bicRegRegRegCallout);
    }

    if (
        mnemonic === "orr" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: orr 3 reg_v reg_v reg_v
        return iteratorPutCalloutWrapper(instr, iterator, orrRegRegRegCallout, orrRegRegRegCallout);
    }

    if (
        mnemonic === "eor" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: eor 3 reg_v reg_v reg_v
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            eorRegRegRegCallout,
            eorRegRegRegCallout
        );
    }

    function eorRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let op2 = parseRegOperand(ctx, operands[2]).name;

        // SIMD register taint in same way as normal register
        let bitmapOp1 = globalState.regs.getBitMap(op1);
        let bitmapOp2 = globalState.regs.getBitMap(op2);

        globalState.regs.fromBitMap(op0, bitmapOp1.union(bitmapOp2));
    }

    function orrRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let op2 = parseRegOperand(ctx, operands[2]).name;
        // TODO: op2 is a register, but it might be shifted, we need to handle it tainted data based on the shift amount
        // TODO: think about this. its an union operation, we shouldnt just taint the destination register
        if (globalState.regs.isTainted(op1) || globalState.regs.isTainted(op2)) {
            globalState.regs.taint(op0);
        }
    }

    function bicRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let op2 = parseRegOperand(ctx, operands[2]).name;

        let bitmapOp1 = globalState.regs.getBitMap(op1);
        let bitmapOp2 = globalState.regs.getBitMap(op2);

        globalState.regs.fromBitMap(op0, bitmapOp1.union(bitmapOp2));
    }

    // for (let ins of ins_list) {
    //     if (mnemonic === ins.mnemonic) {
    //         if (operands.length === ins.operands.length) {
    //             let passOpTypeCheck = true;
    //             for (let i = 0; i < operands.length; i++) {
    //                 if (operands[i].type !== ins.operands[i]) {
    //                     passOpTypeCheck = false;
    //                     break;
    //                 }
    //             }
    //             if (passOpTypeCheck) {
    //                 return iteratorPutCalloutWrapper(
    //                     instr,
    //                     iterator,
    //                     ins.callout
    //                 );
    //             }
    //         }
    //     }
    // }


    if (
        mnemonic === "and" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        // SUPPORTED_SIMD_PATTERN: and 3 reg_v reg_v reg_v
        return iteratorPutCalloutWrapper(instr, iterator, andRegRegRegCallout, andRegRegRegCallout); // FIXME: for SIMD, we currently use the same callout as normal register
    }

    function andRegRegRegCallout(ctx) {
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


    if (
        mnemonic === "ands" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, andsRegRegRegCallout);
    }

    function andsRegRegRegCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;
    
        let op0 = parseRegOperand(ctx, operands[0]).name;
        let op1 = parseRegOperand(ctx, operands[1]).name;
        let op2 = parseRegOperand(ctx, operands[2]).name;
    
        // ANDS: Logical AND and set flags (same as AND but updates condition flags)
        let bitmapOp1 = globalState.regs.getBitMap(op1);
        let bitmapOp2 = globalState.regs.getBitMap(op2);
    
        globalState.regs.fromBitMap(op0, bitmapOp1.union(bitmapOp2));
    }

    if (
        mnemonic === "mvn" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, mvnRegRegCallout);
    }

    function mvnRegRegCallout(ctx) {
        // bitwise NOT - integer arithmetic extension - single source taint propagation
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let dest = parseRegOperand(ctx, operands[0]).name;
        let src = parseRegOperand(ctx, operands[1]).name;

        // MVN: bitwise NOT，target inherits source taint
        globalState.regs.spread(dest, src);
    }

    return null;
}

export { handleLogicalShiftedRegister };
