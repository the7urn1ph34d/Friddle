import { 
    iteratorPutCalloutWrapper, 
    parseRegOperand, 
    parseMemOperand,
    colorLog,
    globalState
} from '../../utils.js';

/*
5.2.8 Load-Acquire / Store-Release
*/
function handleLoadAcquireStoreRelease(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;

    // FIXME: putcallout will get stuck inside the callout, we need to fix this, will loop and call this callout again and again

    /*
    0x72aa01b684: orr w9, w8, #2 at handleLogicalImmediate (bof_dummy_thread.js:724)
    0x72aa01b688: ldxrh w10, [x19] at handleLoadStoreExclusive (bof_dummy_thread.js:563)
    0x72aa01b68c: stlxrh w11, w8, [x19] at handleLoadAcquireStoreRelease (bof_dummy_thread.js:607)
    0x72aa01b690: cbnz w11, #0x72aa01b688

    bbb
    0x72aa01b688: ldxrh w10, [x19] at handleLoadStoreExclusive (bof_dummy_thread.js:563)
    0x72aa01b68c: stlxrh w11, w8, [x19] at handleLoadAcquireStoreRelease (bof_dummy_thread.js:607)
    0x72aa01b690: cbnz w11, #0x72aa01b688

    bbb
    bbb
    bbb
    bbb
    bbb
    bbb
    ...

    need to check registers, and memory see what happened
    */
    if (
        mnemonic === "stlxrh" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(
            instr,
            iterator,
            stlxrhRegRegAddrCallout
        );
    }

    function stlxrhRegRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        // let mnemonic = instr.mnemonic;
        // let operands = instr.operands;
        // let op0 = operands[0].value;
        // let op1 = operands[1].value;
        // let op2 = operands[2].value;

        // let addr = ctx[op2.base].add(op2.disp);

        // globalState.mem.fromRanges(globalState.regs.toRangesWithSize(op1, addr, 2));

        let destReg = parseRegOperand(ctx, instr.operands[0]).name;
        let srcReg = parseRegOperand(ctx, instr.operands[1]).name;
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, instr.operands[2]);
        globalState.mem.fromRanges(globalState.regs.toRangesWithSize(srcReg, memAddr, 2));
        colorLog(
            instr.address +
                " !!!! stlxrhRegRegAddrCallout !!!! " +
                instr.toString(),
            "red"
        );
    }

    if (
        mnemonic === "ldar" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldarRegAddrCallout);
    }

    if (
        mnemonic === "ldarb" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldarbRegAddrCallout);
    }

    if (
        mnemonic === "ldaddl" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldaddlRegRegAddrCallout);
    }

    if (
        mnemonic === "ldaddal" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldaddalRegRegAddrCallout);
    }

    if (
        mnemonic === "ldadd" &&
        operands.length === 3 &&
        operands[0].type === "reg" &&
        operands[1].type === "reg" &&
        operands[2].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, ldaddRegRegAddrCallout);
    }

    function ldarRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let mnemonic = instr.mnemonic;
        let operands = instr.operands;

        let { name: op0, size: op0Size } = parseRegOperand(ctx, operands[0]);
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        globalState.regs.fromBitMap(op0, globalState.mem.toBitMap(memAddr, op0Size));
    }

    // 5. Memory access instruction - Callback function for ldarb instruction
    function ldarbRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let { name: dest, size: destSize } = parseRegOperand(ctx, operands[0]);
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        
        // LDARB: Load-acquire byte (1 byte) from memory with acquire semantics
        globalState.regs.fromBitMap(dest, globalState.mem.toBitMap(memAddr, 1));
        // Clear upper bits for byte load
        if (destSize > 1) {
            globalState.regs.untaintWithOffsetAndSize(dest, 1, destSize - 1);
        }
    }

    // 5. Memory access instruction - Callback function for ldaddl instruction
    function ldaddlRegRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let { name: srcReg } = parseRegOperand(ctx, operands[0]);  // Source register (value to add)
        let { name: destReg, size: destSize } = parseRegOperand(ctx, operands[1]); // Destination register (receives original value)
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[2]);

        // LDADDL: Atomic load-add with release semantics
        // 1. Load original value from memory to destination register
        globalState.regs.fromBitMap(destReg, globalState.mem.toBitMap(memAddr, destSize));
        
        // 2. Atomic add: memory[addr] = memory[addr] + srcReg
        // Memory gets tainted if either original memory or source register was tainted
        if (globalState.mem.isTainted(memAddr, destSize) || globalState.regs.isTainted(srcReg)) {
            globalState.mem.taint(memAddr, destSize);
        }
    }

    // atomic memory operation - ldaddal atomic load-add with acquire-release semantics
    // atomic memory operation - ldaddal atomic load-add with acquire-release semantics
    function ldaddalRegRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let { name: srcReg } = parseRegOperand(ctx, operands[0]);  // Source register (value to add)
        let { name: destReg, size: destSize } = parseRegOperand(ctx, operands[1]); // Destination register (receives original value)
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[2]);

        // LDADDAL: Atomic load-add with acquire-release semantics
        // 1. Load original value from memory to destination register
        globalState.regs.fromBitMap(destReg, globalState.mem.toBitMap(memAddr, destSize));
        
        // 2. Atomic add: memory[addr] = memory[addr] + srcReg
        // Memory gets tainted if either original memory or source register was tainted
        if (globalState.mem.isTainted(memAddr, destSize) || globalState.regs.isTainted(srcReg)) {
            globalState.mem.taint(memAddr, destSize);
        }
    }

    // atomic memory operation - ldadd atomic load-add
    // atomic memory operation - ldadd atomic load-add
    function ldaddRegRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let { name: srcReg } = parseRegOperand(ctx, operands[0]);  // Source register (value to add)
        let { name: destReg, size: destSize } = parseRegOperand(ctx, operands[1]); // Destination register (receives original value)
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[2]);

        // LDADD: Atomic load-add
        // 1. Load original value from memory to destination register
        globalState.regs.fromBitMap(destReg, globalState.mem.toBitMap(memAddr, destSize));
        
        // 2. Atomic add: memory[addr] = memory[addr] + srcReg
        // Memory gets tainted if either original memory or source register was tainted
        if (globalState.mem.isTainted(memAddr, destSize) || globalState.regs.isTainted(srcReg)) {
            globalState.mem.taint(memAddr, destSize);
        }
    }

    if (
        mnemonic === "stlr" &&
        operands.length === 2 &&
        operands[0].type === "reg" &&
        operands[1].type === "mem"
    ) {
        return iteratorPutCalloutWrapper(instr, iterator, stlrRegAddrCallout);
    }

    function stlrRegAddrCallout(ctx) {
        if (!globalState.letsgo) return;
        let instr = Instruction.parse(ctx.pc);
        let operands = instr.operands;

        let op0 = parseRegOperand(ctx, operands[0]);
        let { memAddr: memAddr, isIndirectTainted: isIndirectTainted } =
            parseMemOperand(ctx, operands[1]);
        globalState.mem.fromRanges(globalState.regs.toRanges(op0.name, memAddr));
    }

    return null;
}

export { handleLoadAcquireStoreRelease };
