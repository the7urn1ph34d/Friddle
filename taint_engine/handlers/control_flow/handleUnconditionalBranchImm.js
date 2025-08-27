/*
5.1.2 Unconditional Branch (immediate)
*/
function handleUnconditionalBranchImm(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;
    // we dont handle conditional branch for now
    return null;
}

export { handleUnconditionalBranchImm };