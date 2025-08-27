# Friddle: An Instruction-Level Dynamic Taint Analysis Framework for Detecting Data Leaks on Android and iOS

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Android%20%7C%20iOS-green.svg)
![Architecture](https://img.shields.io/badge/architecture-ARM64-orange.svg)

Friddle is a cross platform, instruction level dynamic taint analysis framework for detecting data leaks in native code on Android and iOS devices. Built on top of Frida's dynamic binary instrumentation capabilities, Friddle provides fine grained information flow tracking without requiring modifications to the operating system or application source code.

## 🚀 Key Features

- **Cross Platform Support**: Works on both Android and iOS platforms
- **Instruction Level Analysis**: Provides fine grained ARM64 instruction level taint tracking
- **No System Modification Required**: Operates without modifying OS or applications
- **Comprehensive ARM64 Support**: Handles 98.5% of actual instruction execution frequency
- **Advanced Flow Detection**: Tracks both explicit and implicit information flows
- **Crypto Aware**: Supports analysis of cryptographic operations including AES
- **Modular Architecture**: Extensible design with clear separation of concerns

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [FriddleBench](#friddlebench)
- [Usage Examples](#usage-examples)
- [API Documentation](#api-documentation)
- [Performance](#performance)
- [Research Background](#research-background)
- [Contributing](#contributing)
- [License](#license)

## 🏗️ Architecture Overview

Friddle employs a layered, modular architecture consisting of three main components:

### 1. Taint Core
The data foundation responsible for storing and maintaining taint marks:
- **Register Taint**: Byte level bitmap tracking for general purpose and SIMD registers
- **Memory Taint**: Interval tree managing tainted regions across memory space
- **Register Aliasing Support**: Handles ARM64 register aliasing (x0/w0, q0/d0/s0, etc.)

### 2. Propagation Engine
The core computational component implementing taint propagation logic:
- **Instruction Handlers**: Modular handlers for different ARM64 instruction categories
- **Runtime Callouts**: Efficient runtime taint state updates
- **Operand Parsing**: Complex ARM64 operand format support with extensions and shifts

### 3. Instrumentation Layer
Direct interface with Frida's Stalker for runtime code rewriting:
- **JIT Compilation**: Real time basic block instrumentation and compilation
- **Cross Platform Support**: Unified interface for Android and iOS platforms

The architecture consists of three main layers:

**Application Layer** → **Instrumentation Layer** → **Propagation Engine** → **Taint Core**

- **Instrumentation Layer**: Uses Frida Stalker for basic block capture, rewriting, JIT compilation and cross platform runtime support
- **Propagation Engine**: Contains instruction handlers for memory access, arithmetic/logic, control flow, floating point/SIMD, crypto extensions, and vector operations  
- **Taint Core**: Split into Register Taint (bitmap storage, byte granularity, aliasing support) and Memory Taint (interval tree, region merging, efficient queries)

## 📦 Installation

### Prerequisites

- **Frida**: Version 16.5.6 or later
- **Node.js**: For running JavaScript based components
- **Platform specific tools**:
  - Android: Android SDK, ADB
  - iOS: Xcode, iOS Developer Tools

### Basic Setup

1. **Clone the repository:**
```bash
git clone https://github.com/the7urn1ph34d/Friddle.git
cd friddle
```

2. **Install Frida:**
```bash
pip install frida-tools
```

3. **Set up the taint engine:**
```bash
cd taint_engine
chmod +x compile_frida.sh
./compile_frida.sh
```

## 🚀 Quick Start

### Android Analysis

1. **Prepare your Android device/emulator:**
```bash
adb devices
frida-ps -U
```

2. **Run the Android test application:**
```bash
cd FriddleBench/AndroidTest
./gradlew installDebug
```

3. **Start taint analysis:**
```bash
frida -U -l taint_engine/android.js -f com.friddle.androidtest --no-pause
```

### iOS Analysis

1. **Prepare your iOS device:**
```bash
frida-ps -U
```

2. **Build and install the iOS test app:**
```bash
cd FriddleBench/iostest
open iostest.xcodeproj
# Build and install through Xcode
```

3. **Start taint analysis:**
```bash
frida -U -l taint_engine/ios.js -f iostest --no-pause
```

## 🧪 FriddleBench

FriddleBench is our comprehensive benchmark suite designed specifically for evaluating taint analysis tools on mobile native code. It includes test cases for:

### Test Scenarios

1. **String Operations**
   - Direct memory copying (`strcpy`)
   - Data transformation scenarios

2. **Encoding Operations**
   - Base64 encoding/decoding
   - Custom encoding schemes

3. **Cryptographic Operations**
   - AES encryption (both library and custom implementations)
   - Implicit flows through table lookups
   - S-box operations

4. **False Positive Testing**
   - Clean data path verification
   - Precision validation scenarios

### Benchmark Structure

```
FriddleBench/
├── AndroidTest/          # Android native test application
│   ├── app/src/main/
│   │   ├── java/         # Java UI and JNI bindings
│   │   └── cpp/          # Native C++ test implementations
│   └── build.gradle      # Android build configuration
└── iostest/              # iOS native test application
    ├── iostest/
    │   ├── ViewController.m  # iOS UI implementation
    │   └── native-lib.cpp    # Native C++ test implementations
    └── iostest.xcodeproj     # Xcode project file
```

## 💡 Usage Examples

### Basic Taint Analysis

```javascript
import { init_taint, start_taint, stop_taint } from './taint_engine.js';

// Initialize taint analysis
var source_addr = Module.findExportByName('libmyapp.so', 'source_function');
var sink_addr = Module.findExportByName('libmyapp.so', 'sink_function');

init_taint(source_addr, sink_addr);
start_taint();

// Analysis will run automatically between source and sink
```

### Custom Handler Registration

```javascript
// Register custom instruction handler
registerStalkerHandle({
    onEnter: function(instr, iterator) {
        if (instr.mnemonic === 'custom_op') {
            return iteratorPutCalloutWrapper(instr, iterator, customCallout);
        }
    }
});

function customCallout(ctx) {
    // Custom taint propagation logic
    let src_reg = parseRegOperand(ctx, operands[0]);
    let dst_reg = parseRegOperand(ctx, operands[1]);
    
    if (globalState.regs.isTainted(src_reg.name)) {
        globalState.regs.taint(dst_reg.name);
    }
}
```

### Memory Taint Tracking

```javascript
// Check if memory region is tainted
if (globalState.mem.isTainted(buffer_addr, buffer_size)) {
    console.log("Buffer contains tainted data");
}

// Taint a memory region
globalState.mem.taint(start_addr, size);

// Check if memory is fully tainted
if (globalState.mem.isFullyTainted(addr, size)) {
    console.log("Entire region is tainted");
}
```

## 📚 API Documentation

### Core APIs

#### Taint Core Operations

```javascript
// === Register Operations ===
globalState.regs.taint(register_name)                              // Mark entire register as tainted
globalState.regs.taintWithOffsetAndSize(reg, offset, size)         // Mark specific bytes in register
globalState.regs.untaint(register_name)                            // Clear entire register taint
globalState.regs.untaintWithOffsetAndSize(reg, offset, size)       // Clear specific bytes in register
globalState.regs.isTainted(register_name)                          // Check if any bytes are tainted
globalState.regs.isTaintedWithOffsetAndSize(reg, offset, size)     // Check specific bytes for taint
globalState.regs.isFullyTainted(register_name)                     // Check if all bytes are tainted
globalState.regs.isFullyTaintedWithOffsetAndSize(reg, offset, size) // Check if specific bytes fully tainted
globalState.regs.spread(dst_reg, src_reg)                          // Copy taint state from src to dst
globalState.regs.fromBitMap(register_name, bitmap)                 // Set register taint from bitmap
globalState.regs.getBitMap(register_name)                          // Get register's taint bitmap
globalState.regs.getBitMapWithRegOffsetAndSize(reg, offset, size)  // Get partial bitmap
globalState.regs.setBitMapWithRegOffset(reg, offset, bitmap)       // Set partial bitmap
globalState.regs.toArray()                                         // Get array of tainted registers
globalState.regs.toRanges(reg, base_addr)                          // Convert register taint to memory ranges
globalState.regs.toRangesWithSize(reg, base_addr, size)            // Convert with specific size
globalState.regs.clear()                                           // Clear all register taints

// === Memory Operations ===
globalState.mem.taint(addr, size)                                  // Mark memory region as tainted
globalState.mem.untaint(addr, size)                                // Clear memory region taint
globalState.mem.isTainted(addr, size)                              // Check if any bytes are tainted
globalState.mem.isFullyTainted(addr, size)                         // Check if all bytes are tainted
globalState.mem.toBitMap(addr, size)                               // Convert memory taint to bitmap
globalState.mem.fromRanges(ranges_array)                           // Set memory taint from ranges
globalState.mem.toArray()                                          // Get array of tainted memory ranges
globalState.mem.clear()                                            // Clear all memory taints
globalState.mem.prettyPrint()                                      // Debug print interval tree structure

// === BitMap Operations ===
bitmap.get(offset)                                                 // Get bit at offset
bitmap.set(offset, boolean)                                        // Set bit at offset
bitmap.flip(offset)                                                // Toggle bit at offset
bitmap.fill()                                                      // Set all bits to 1
bitmap.clear()                                                     // Set all bits to 0
bitmap.union(other_bitmap)                                         // Bitwise OR with another bitmap
bitmap.reverse()                                                   // Reverse bit order
bitmap.prettyPrint(endian, length)                                 // Human readable bit representation

// === Interval Tree Operations ===
intervalTree.add(interval)                                         // Add interval [start, end)
intervalTree.remove(interval)                                      // Remove interval with merging
intervalTree.contains(point)                                       // Check if point is contained
intervalTree.intersects(interval)                                  // Check if interval intersects
intervalTree.intersection(interval)                                // Get intersecting intervals
intervalTree.clear()                                               // Clear all intervals
intervalTree.prettyPrint()                                         // Debug print tree structure
```

#### Utility Functions

```javascript
// === Core Utility Functions ===
initializeUtils()                                                   // Initialize global state
colorLog(message, color)                                           // Colored console logging
assert(ctx, condition, message)                                    // Assertion with context info
iteratorPutCalloutWrapper(instr, iterator, callout1, callout2)     // Wrap callouts for SIMD/non-SIMD
readMemVal(ctx, memAddr, size)                                     // Read memory value by size
readRegVal(ctx, register_name)                                     // Read register value with aliasing

// === Operand Parsing Functions ===
parseRegOperand(ctx, operand)                                      // Parse register with extensions/shifts
parseMemOperand(ctx, operand)                                      // Parse memory operand and compute address
parseImmOperand(ctx, operand)                                      // Parse immediate operand with shifts
parseVector(ctx, vector_operand)                                   // Parse SIMD vector operand format

// === SIMD/Vector Operations ===
taintSIMDRegFromReg(ctx, dest_simd_reg, src_reg)                  // Taint SIMD register from register
taintSIMDRegFromMem(ctx, simd_reg, mem_addr)                      // Taint SIMD register from memory
taintMemFromSIMDReg(ctx, mem_addr, simd_reg)                      // Taint memory from SIMD register

// === Condition Flag Checking ===
checkNZCVFlag(ctx)                                                 // Check ARM64 condition flags (eq, ne, etc.)

// === Configuration Functions ===
globalState.enableImplicitTaint                                    // Enable/disable implicit flow tracking
globalState.show_bb_seperator                                     // Show basic block separators in debug
globalState.print_all_compile_ins                                 // Print all instructions during compilation
globalState.print_all_instr_json                                  // Print instruction JSON during runtime
globalState.ignore_letsgo_in_printDebugInfo                       // Debug printing configuration
```

### Handler Categories

Friddle supports handlers for the following ARM64 instruction categories:

- **Memory Access**: `handleLoadStoreSingleReg`, `handleLoadStorePair`
- **Arithmetic**: `handleArithmeticImmediate`, `handleArithmeticShiftedRegister`
- **Logic**: `handleLogicalImmediate`, `handleLogicalShiftedRegister`
- **Floating Point/SIMD**: `handleFloatingPointArithmetic2Source`, `handleVectorArithmetic`
- **Control Flow**: `handleConditionalBranch`, `handleUnconditionalBranchImm`
- **Crypto Extensions**: `handleCryptoExtension`

## ⚡ Performance

Our evaluation shows that Friddle provides comprehensive ARM64 instruction coverage while maintaining reasonable performance overhead:

### Instruction Coverage
- **98.5%** of actual instruction execution frequency supported
- **635 Android system libraries** analyzed for coverage statistics
- Focus on the most critical data flow patterns

### Performance Characteristics
- Instruction level granularity with dynamic optimization
- Efficient bitmap and interval tree data structures
- JIT compilation reduces runtime overhead
- Modular handler system minimizes unnecessary processing

## 🔬 Research Background

Friddle was developed as part of a Master's thesis research project at Vrije Universiteit Amsterdam, addressing the following research questions:

### Research Questions Addressed

1. **RQ1: Correctness** - Can Friddle correctly detect tainted data movement across different transformation scenarios (basic operations, table lookups, encryption) while avoiding false positives?

2. **RQ2: Performance Overhead** - What is the performance impact of Friddle's instruction level dynamic instrumentation compared to native execution?

3. **RQ3: Instruction Coverage** - What proportion of the ARM64 instruction set, particularly data flow related instructions, can Friddle support?

### Key Contributions

- **Modular, extensible dynamic taint analysis engine** for mobile native code
- **Cross platform support** demonstrating information flow tracking on both Android and iOS
- **Experimental validation** using FriddleBench in realistic scenarios including implicit flows and cryptographic operations
- **Comprehensive ARM64 instruction support** with detailed propagation rules

## 📖 Academic Reference

If you use Friddle in your research, please cite:

```bibtex
@mastersthesis{gao2025friddle,
  title={Friddle: An Instruction-Level Dynamic Taint Analysis Framework for Detecting Data Leaks on Android and iOS},
  author={Simon Gao},
  school={Vrije Universiteit Amsterdam},
  year={2025},
  type={Master's Thesis},
  department={Computer Security}
}
```

## 🤝 Contributing

We welcome contributions to Friddle! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on:

- Code style and standards
- Testing requirements
- Pull request process
- Issue reporting

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes and add tests
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Frida Project** - For providing the dynamic instrumentation framework
- **VUSec** - For research support and guidance
- **Andrea Fioraldi** ([taint-with-frida](https://github.com/andreafioraldi/taint-with-frida)) - For the original x86/64 taint analysis concept that inspired this work

---

*Friddle is a research project developed for academic purposes. Use responsibly and in accordance with applicable laws and ethical guidelines.*