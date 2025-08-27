/*
5.1.3 Unconditional Branch (register)
*/
function handleUnconditionalBranchReg(instr, iterator) {
    let operands = instr.operands;
    let mnemonic = instr.mnemonic;
    // we dont handle conditional branch for now
    return null;
}

export { handleUnconditionalBranchReg };