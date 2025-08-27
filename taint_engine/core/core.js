import { BitMap } from "./bitmap.js";
import { IntervalTree } from "./interval-tree.js";

export class Registers {
    constructor(arch) {
        this.arch = arch;
        this.registerBitmaps = {};
        // Create a mapping so that registers sharing the same offset share the same BitMap.
        const offsetMap = {};
        for (let reg in arch.registers) {
            const [offset, size] = arch.registers[reg];
            if (offsetMap.hasOwnProperty(offset)) {
                // Use the existing BitMap even if the declared size differs.
                this.registerBitmaps[reg] = offsetMap[offset];
            } else {
                // For the first encountered register at this offset, use its declared size.
                const bmp = new BitMap(size);
                offsetMap[offset] = bmp;
                this.registerBitmaps[reg] = bmp;
            }
        }
    }

    taint(reg) {
        const declaredSize = this.arch.registers[reg][1];
        this.taintWithOffsetAndSize(reg, 0, declaredSize);
    }

    taintWithOffsetAndSize(reg, offset, size) {
        if (reg === 'wzr' || reg === 'xzr') return;
        const bmp = this.registerBitmaps[reg];
        for (let i = offset; i < offset + size; i++) {
            bmp.set(i, true);
        }
    }

    untaint(reg) {
        const declaredSize = this.arch.registers[reg][1];
        this.untaintWithOffsetAndSize(reg, 0, declaredSize);
    }

    untaintWithOffsetAndSize(reg, offset, size) {
        if (reg === 'wzr' || reg === 'xzr') return;
        const bmp = this.registerBitmaps[reg];
        for (let i = offset; i < offset + size; i++) {
            bmp.set(i, false);
        }
    }

    isTainted(reg) {
        const declaredSize = this.arch.registers[reg][1];
        return this.isTaintedWithOffsetAndSize(reg, 0, declaredSize);
    }

    isTaintedWithOffsetAndSize(reg, offset, size) {
        const bmp = this.registerBitmaps[reg];
        const declaredSize = this.arch.registers[reg][1];
        // check size is less than or equal to the declared size.
        if (offset + size > declaredSize) {
            throw new Error(`Offset + size exceeds declared size: ${offset} + ${size} > ${declaredSize}`);
        }

        for (let i = offset; i < offset + size; i++) {
            if (bmp.get(i)) return true;
        }
        return false;
    }
    
    isFullyTainted(reg) {
        const declaredSize = this.arch.registers[reg][1];
        return this.isFullyTaintedWithOffsetAndSize(reg, 0, declaredSize);
    }

    isFullyTaintedWithOffsetAndSize(reg, offset, size) {
        const bmp = this.registerBitmaps[reg];
        const declaredSize = this.arch.registers[reg][1];
        // check size is less than or equal to the declared size.
        if (offset + size > declaredSize) {
            throw new Error(`Offset + size exceeds declared size: ${offset} + ${size} > ${declaredSize}`);
        }

        for (let i = offset; i < offset + size; i++) {
            if (!bmp.get(i)) return false;
        }
        return true;
    }
    
    toArray() {
        const arr = [];
        for (let reg in this.arch.registers) {
            if (reg === 'wzr' || reg === 'xzr') continue;
            if (this.isTainted(reg)) {
                const declaredSize = this.arch.registers[reg][1];
                arr.push(`${reg}(${this.registerBitmaps[reg].prettyPrint("little", declaredSize)})`);
            }
        }
        return arr;
    }

    toRanges(reg, base) {
        const declaredSize = this.arch.registers[reg][1];
        return this.toRangesWithRegOffsetAndSize(reg, base, 0, declaredSize);
    }

    toRangesWithSize(reg, base, size) {
        const declaredSize = this.arch.registers[reg][1];
        // make sure size is less than or equal to declared size.
        if (size > declaredSize) {
            throw new Error(`Size exceeds declared size: ${size} > ${declaredSize}`);
        }
        return this.toRangesWithRegOffsetAndSize(reg, base, 0, size);
    }

    // This offset is reg offset, not mem offset. 
    toRangesWithRegOffsetAndSize(reg, base, regOffset, size) {
        const regBitMap = this.registerBitmaps[reg];
        const declaredSize = this.arch.registers[reg][1];
        const ranges = [];

        // check size is less than or equal to the declared size.
        if (regOffset + size > declaredSize) {
            throw new Error(`Offset + size exceeds declared size: ${regOffset} + ${size} > ${declaredSize}`);
        }

        for (let i = regOffset; i < regOffset + size; i++) {
            if (regBitMap.get(i)) {
                const addr = base.add(i - regOffset);
                if (ranges.length === 0) {
                    ranges.push([addr, addr]);
                }
                if (ranges[ranges.length - 1][1].equals(addr)) {
                    ranges[ranges.length - 1][1] = addr.add(1);
                } else {
                    ranges.push([addr, addr.add(1)]);
                }
            }
        }
        return ranges;
    }

    // Copies the taint state from the source register to the destination register.
    spread(destReg, srcReg) {
        if (destReg === 'wzr' || destReg === 'xzr') return;
        this.fromBitMap(destReg, this.getBitMap(srcReg));
    }

    // Copies a provided BitMap's taint into the register's BitMap.
    fromBitMap(reg, bmap) {
        if (reg === 'wzr' || reg === 'xzr') return;
        this.setBitMapWithRegOffset(reg, 0, bmap);
    }

    setBitMapWithRegOffset(reg, regOffset, bmap) {
        if (reg === 'wzr' || reg === 'xzr') return;
        const regBitMap = this.registerBitmaps[reg];
        const declaredSize = this.arch.registers[reg][1];

        // make sure regOffset + size is less than or equal to the declared size.
        if (regOffset + bmap._size > declaredSize) {
            throw new Error(`Offset + size exceeds declared size: ${regOffset} + ${bmap._size} > ${declaredSize}`);
        }
        for (let i = regOffset; i < regOffset + bmap._size; i++) {
            regBitMap.set(i, bmap.get(i - regOffset));
        }
    }

    // Returns the BitMap associated with a register.
    getBitMap(reg) {
        return this.getBitMapWithRegOffsetAndSize(reg, 0, this.arch.registers[reg][1]);
    }

    getBitMapWithRegOffsetAndSize(reg, regOffset, size) {
        const regBitMap = this.registerBitmaps[reg];
        const declaredSize = this.arch.registers[reg][1];
        const bmap = new BitMap(size);

        // make sure regOffset + size is less than or equal to the declared size.
        if (regOffset + size > declaredSize) {
            throw new Error(`Offset + size exceeds declared size: ${regOffset} + ${size} > ${declaredSize}`);
        }

        for (let i = regOffset; i < regOffset + size; i++) {
            bmap.set(i - regOffset, regBitMap.get(i));
        }
        return bmap;
    }

    // Clears taint in all registers.
    clear() {
        for (let reg in this.registerBitmaps) {
            const declaredSize = this.arch.registers[reg] ? this.arch.registers[reg][1] : this.registerBitmaps[reg]._size;
            for (let i = 0; i < declaredSize; i++) {
                this.registerBitmaps[reg].set(i, false);
            }
        }
    }
}

// The Memory class remains unchanged.
export class Memory {
    constructor() {
        this.memTaintTree = new IntervalTree();
    }

    taint(addr, size) {
        this.memTaintTree.add([addr, addr.add(size)]);
    }

    untaint(addr, size) {
        this.memTaintTree.remove([addr, addr.add(size)]);
    }

    isTainted(addr, size) {
        return this.memTaintTree.intersects([addr, addr.add(size)]);
    }

    isFullyTainted(addr, size) {
        const intersections = this.memTaintTree.intersection([addr, addr.add(size)]);
        if (intersections.length === 0) return false;
        intersections.sort((a, b) => a[0].compare(b[0]));
        let current = addr;
        for (const [start, end] of intersections) {
            if (start.compare(current) > 0) return false;
            if (end.compare(current) > 0) current = end;
            if (current.compare(addr.add(size)) >= 0) return true;
        }
        return current.compare(addr.add(size)) >= 0;
    }

    toArray() {
        function copyInterval(interval) {
            return [interval[0], interval[1]];
        }
        const helper = (node, arr) => {
            if (!node) return arr;
            helper(node.left, arr);
            const currentInterval = copyInterval(node.interval);
            if (arr.length > 0 && arr[arr.length - 1][1].compare(currentInterval[0]) >= 0) {
                if (arr[arr.length - 1][1].compare(currentInterval[1]) < 0) {
                    arr[arr.length - 1][1] = currentInterval[1];
                }
            } else {
                arr.push(currentInterval);
            }
            helper(node.right, arr);
            return arr;
        };
        return helper(this.memTaintTree.root, []);
    }

    fromRanges(ranges) {
        for (const range of ranges) {
            this.memTaintTree.add(range);
        }
    }

    toBitMap(addr, size) {
        const inter = this.memTaintTree.intersection([addr, addr.add(size)]);
        const bmap = new BitMap(size);
        for (const range of inter) {
            for (let j = range[0].sub(addr).toInt32(); j < range[1].sub(addr).toInt32(); ++j) {
                bmap.set(j, true);
            }
        }
        return bmap;
    }

    clear() {
        this.memTaintTree.clear();
    }

    prettyPrint() {
        return this.memTaintTree.prettyPrint();
    }
}