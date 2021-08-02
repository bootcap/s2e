///
/// Copyright (C) 2017, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/SymbolicHardwareHook.h>
#include <s2e/Utils.h>

#include <llvm/Support/CommandLine.h>

#include "RatavaDump.h"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <s2e/cpu.h>

namespace {
llvm::cl::opt<bool> DebugSymbHw("debug-ratava-dump", llvm::cl::init(false));
}

namespace s2e {
namespace plugins {
namespace hw {

extern "C" {
static bool symbhw_is_mmio_symbolic(struct MemoryDesc *mr, uint64_t physaddr, uint64_t size, void *opaque);
}

int RatavaDump::read_log_count = 0;
int RatavaDump::write_log_count = 0;

std::ofstream RatavaOut("/home/cap/uEmu/test_log/ratava_log.txt"); 

struct timeval current_time(){
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv;
}

static klee::ref<klee::Expr> symbhw_symbread(struct MemoryDesc *mr, uint64_t physaddress,
                                             const klee::ref<klee::Expr> &value, SymbolicHardwareAccessType type,
                                             void *opaque);

static void symbhw_symbwrite(struct MemoryDesc *mr, uint64_t physaddress, const klee::ref<klee::Expr> &value,
                             SymbolicHardwareAccessType type, void *opaque);

S2E_DEFINE_PLUGIN(RatavaDump, "RatavaDump S2E plugin", "", );

void RatavaDump::initialize() {
    if (!configSymbolicMmioRange()) {
        getWarningsStream() << "Could not parse config\n";
        exit(-1);
    }

    g_symbolicMemoryHook = SymbolicMemoryHook(symbhw_is_mmio_symbolic, symbhw_symbread, symbhw_symbwrite, this);
    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(sigc::mem_fun(*this, &RatavaDump::onTranslateInstruction));
    s2e()->getCorePlugin()->onConcreteDataMemoryAccess.connect(sigc::mem_fun(*this, &RatavaDump::onConcreteDataMemoryAccess));
}

void RatavaDump::onTranslateInstruction(ExecutionSignal *signal,
                                                S2EExecutionState *state,
                                                TranslationBlock *tb,
                                                uint64_t pc) {
    // When we find an interesting address, ask S2E to invoke our callback when the address is actually
    signal->connect(sigc::mem_fun(*this, &RatavaDump::onInstructionExecution));
}

void RatavaDump::onConcreteDataMemoryAccess(S2EExecutionState *state,
                 uint64_t v_addr, // virtual address
                 uint64_t value, // value
                 uint8_t size, // size
                 unsigned flag) { // flags
    uint64_t s = size;
    RatavaOut << "Access Memory: virtual_address[" << v_addr
	   << "] value[" << value
	   << "] size[" << s
	   << "] flag[" << flag
	   << "] \n";
}

void RatavaDump::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
    RatavaOut << "Executing instruction at " << hexval(pc) << '\n';
}

bool RatavaDump::configSymbolicMmioRange(void) {
    SymbolicMmioRange m;

    // ARM MMIO range 0x40000000-0x60000000
    m.first = 0x40000000;
    m.second = 0x5fffffff;

    getDebugStream() << "Adding symbolic mmio range: " << hexval(m.first) << " - " << hexval(m.second) << "\n";
    m_mmio.push_back(m);

    return true;
}

template <typename T, typename U> inline bool RatavaDump::isSymbolic(T ports, U port) {
    for (auto &p : ports) {
        if (port >= p.first && port <= p.second) {
            return true;
        }
    }

    return false;
}


bool RatavaDump::isMmioSymbolic(uint64_t physAddr) {
    return isSymbolic(m_mmio, physAddr);
}

static void SymbHwGetConcolicVector(uint64_t in, unsigned size, ConcreteArray &out) {
    union {
        // XXX: assumes little endianness!
        uint64_t value;
        uint8_t array[8];
    };

    value = in;
    out.resize(size);
    for (unsigned i = 0; i < size; ++i) {
        out[i] = array[i];
    }
}

klee::ref<klee::Expr> RatavaDump::createExpression(S2EExecutionState *state, SymbolicHardwareAccessType type,
                                                         uint64_t address, unsigned size, uint64_t concreteValue) {

    std::stringstream ss;
    switch (type) {
        case SYMB_MMIO:
            ss << "iommuread_";
            break;
        case SYMB_DMA:
            ss << "dmaread_";
            break;
        case SYMB_PORT:
            ss << "portread_";
            break;
    }

    ss << hexval(address) << "@" << hexval(state->regs()->getPc());
    ss << "_" << hexval(size);

    uint32_t NLP_value = concreteValue;
    onSymbolicNLPRegisterReadEvent.emit(state, type, address, size, &NLP_value);

    getDebugStream(g_s2e_state) << ss.str() << " size " << hexval(size)
                                << "NLP value =" << hexval(NLP_value) << "\n";

    ConcreteArray concolicValue;
    SymbHwGetConcolicVector(concreteValue, size, concolicValue);
    return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
}

//////////////////////////////////////////////////////////////////////
static bool symbhw_is_mmio_symbolic(struct MemoryDesc *mr, uint64_t physaddr, uint64_t size, void *opaque) {
    RatavaDump *hw = static_cast<RatavaDump *>(opaque);
    return hw->isMmioSymbolic(physaddr);
}

// XXX: remove MemoryDesc
static klee::ref<klee::Expr> symbhw_symbread(struct MemoryDesc *mr, uint64_t physaddress,
                                             const klee::ref<klee::Expr> &value, SymbolicHardwareAccessType type,
                                             void *opaque) {
    RatavaDump *hw = static_cast<RatavaDump *>(opaque);

    if (DebugSymbHw) {
        hw->getDebugStream(g_s2e_state) << "reading mmio " << hexval(physaddress) << " value: " << value << "\n";
    }

    unsigned size = value->getWidth() / 8;
    uint64_t concreteValue = g_s2e_state->toConstantSilent(value)->getZExtValue();

    RatavaOut << "read mmio: [" << physaddress << "] value: [" << value << "] concreteValue: [" << concreteValue << "]" << std::endl; 

    return hw->createExpression(g_s2e_state, SYMB_MMIO, physaddress, size, concreteValue);
}

static void symbhw_symbwrite(struct MemoryDesc *mr, uint64_t physaddress, const klee::ref<klee::Expr> &value,
                             SymbolicHardwareAccessType type, void *opaque) {
    RatavaDump *hw = static_cast<RatavaDump *>(opaque);
    uint32_t curPc = g_s2e_state->regs()->getPc();

    hw->getDebugStream() << "writing mmio " << hexval(physaddress) << " value: " << value
                                        << " pc: " << hexval(curPc) << "\n";
    if (DebugSymbHw) {
        hw->getDebugStream(g_s2e_state) << "writing mmio " << hexval(physaddress) << " value: " << value
                                        << " pc: " << hexval(curPc) << "\n";
    }

    RatavaOut << "write mmio: [" << physaddress << "] value: [" << value << "]" << " pc: " << hexval(curPc) << std::endl; 
    value->printKind(hw->getDebugStream(), klee::Expr::Kind::Concat); 

    hw->onWritePeripheral(g_s2e_state, physaddress, value);
}

void RatavaDump::onWritePeripheral(S2EExecutionState *state, uint64_t phaddr,
                                                const klee::ref<klee::Expr> &value) {

    uint32_t writeConcreteValue;
    if (isa<klee::ConstantExpr>(value)) {
        klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(value);
        writeConcreteValue = ce->getZExtValue();
        getDebugStream() << "writing mmio " << hexval(phaddr) << " concrete value: " << hexval(writeConcreteValue)
                         << "\n";
    } else {
        // evaluate symbolic regs
        klee::ref<klee::ConstantExpr> ce;
        ce = dyn_cast<klee::ConstantExpr>(g_s2e_state->concolics->evaluate(value));
        writeConcreteValue = ce->getZExtValue();
        getDebugStream() << "writing mmio " << hexval(phaddr) << " symbolic to concrete value: " << hexval(writeConcreteValue) << "\n";
    }

    onSymbolicNLPRegisterWriteEvent.emit(g_s2e_state, SYMB_MMIO, phaddr, writeConcreteValue);

}

} // namespace hw
} // namespace plugins
} // namespace s2e
