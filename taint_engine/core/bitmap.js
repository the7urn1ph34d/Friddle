'use strict';

// Compact BitMap data structure
// Memory-efficient array of boolean flags
export class BitMap {
    constructor(size) {
        this._size = size;
        this._cols = 8;
        this._shift = 3;
        this._rows = Math.ceil(size / this._cols);
        this._buf = new ArrayBuffer(this._rows);
        this._bin = new Uint8Array(this._buf);
    }
    
    _checkBounds(off) {
        if (off < 0 || off >= this._size) {
            throw new RangeError(`BitMap: offset ${off} is out of bounds (size ${this._size}).`);
        }
    }

    // Gets the boolean value at the specified offset
    get(off) {
        this._checkBounds(off);
        const row = off >> this._shift;
        const col = off % this._cols;
        const bit = 1 << col;
        return (this._bin[row] & bit) !== 0;
    }

    // Sets a boolean value at the specified offset
    set(off, bool) {
        this._checkBounds(off);
        const row = off >> this._shift;
        const col = off % this._cols;
        const bit = 1 << col;
        if (bool) {
            this._bin[row] |= bit;
        } else {
            // Clear the bit using bitwise NOT.
            this._bin[row] &= ~bit;
        }
    }

    // Flips the boolean value at the specified offset
    flip(off) {
        this._checkBounds(off);
        const row = Math.floor(off / this._cols);
        const col = off % this._cols;
        const bit = 1 << col;
        this._bin[row] ^= bit;
    }

    // Resets all bits to 1
    fill() {
        this._bin.fill(0xFF);
        // Clear extra bits in the last byte if size is not a multiple of 8.
        const extraBits = (this._rows * this._cols) - this._size;
        if (extraBits > 0) {
            const mask = (1 << (this._cols - extraBits)) - 1;
            this._bin[this._rows - 1] &= mask;
        }
    }

    // Resets all bits to 0
    clear() {
        this._bin.fill(0);
    }
    // TODO: should we put this function here? instead of in the core.js?
    // Returns a new BitMap that is the union (bitwise OR) of this and another BitMap
    union(other) {


        // when size is not the same, we need to create a new BitMap with the larger size.
        
        if (this._size !== other._size) {
            // TODO: should we throw an error here?
            // console.log("union in bitmap.js", this._size, other._size);
        }

        const result = new BitMap(Math.max(this._size, other._size));
        for (let i = 0; i < this._rows; i++) {
            result._bin[i] = this._bin[i] | other._bin[i];
        }
        return result;
    }
    // TODO: should we put this function here? instead of in the core.js?
    // Returns a new BitMap with the bits reversed
    reverse() {
        const result = new BitMap(this._size);
        for (let i = 0; i < this._size; i++) {
            result.set(this._size - 1 - i, this.get(i));
        }
        return result;
    }

    prettyPrint(endian = "little", length = this._size) {
        let parts = [];
        if (endian === "little") {
            for (let i = 0; i < length; i++) {
                parts.push(this.get(i) ? "1" : "0");
            }
        } else {
            for (let i = length - 1; i >= 0; i--) {
                parts.push(this.get(i) ? "1" : "0");
            }
        }
        return parts.join(".");
    }
    
}
