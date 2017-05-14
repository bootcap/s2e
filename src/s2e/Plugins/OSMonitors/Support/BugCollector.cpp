///
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <iostream>
#include <sstream>

#include <s2e/Plugins/OSMonitors/Windows/BlueScreenInterceptor.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsCrashDumpGenerator.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>

#include "BugCollector.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(BugCollector, "This plugin aggregates various sources of Windows crashes", "", "WindowsMonitor",
                  "WindowsCrashDumpGenerator", "BlueScreeInterceptor");

void BugCollector::initialize() {
    m_windowsMonitor = s2e()->getPlugin<WindowsMonitor>();
    m_bsodInterceptor = s2e()->getPlugin<BlueScreenInterceptor>();
    m_bsodGenerator = s2e()->getPlugin<WindowsCrashDumpGenerator>();

    // Crash dumps may be heavy, disable them by default
    m_generateCrashDump = s2e()->getConfig()->getBool(getConfigKey() + ".generateCrashDump", false);

    // Dumps may be vers large, compress them by default
    m_compressDumps = s2e()->getConfig()->getBool(getConfigKey() + ".compressDumps", true);

    // Turn this off to let other plugins decide whether to kill the state or not
    // This option only applies to user-space crashes
    m_terminateOnCrash = s2e()->getConfig()->getBool(getConfigKey() + ".terminateOnCrash", true);

    if (m_generateCrashDump) {
        m_bsodInterceptor->onBlueScreen.connect(sigc::mem_fun(*this, &BugCollector::onBlueScreen));
    }
}

void BugCollector::generateCrashDump(S2EExecutionState *state, const vmi::windows::BugCheckDescription *info,
                                     bool isManual) {
    if (!m_generateCrashDump) {
        getWarningsStream(state) << "Crash dump generation disabled\n";
        return;
    }

    bool ret;
    std::string path = m_bsodGenerator->getPathForDump(state);

    if (isManual) {
        ret = m_bsodGenerator->generateManualDump(state, path, info);
    } else {
        ret = m_bsodGenerator->generateDump(state, path, info);
    }

    if (!ret) {
        return;
    }

    if (m_compressDumps) {
        compress_file(path);
    }
}

void BugCollector::onBlueScreen(S2EExecutionState *state, vmi::windows::BugCheckDescription *info) {
    onKernelModeCrash.emit(state, *info);
    generateCrashDump(state, info, false);

    // There is no point of letting the state up at this point, the guest is stuck with a BSOD
    s2e()->getExecutor()->terminateStateEarly(*state, "BSOD");
}

/*****************************************************************/

void BugCollector::opUserModeCrash(S2EExecutionState *state, uint64_t guestDataPtr, const S2E_BUG_COMMAND &command) {
    WindowsUserModeCrash crash;
    crash.Pid = command.UserModeCrash.Pid;
    crash.ExceptionCode = command.UserModeCrash.ExceptionCode;
    crash.ExceptionAddress = command.UserModeCrash.ExceptionAddress;
    crash.ExceptionFlags = command.UserModeCrash.ExceptionFlags;

    bool ret = true;
    ret &= state->mem()->readString(command.UserModeCrash.ProgramName, crash.ProgramName);
    if (!ret) {
        getWarningsStream(state) << "could not read program name\n";
        return;
    }

    crash.CrashDumpHeader.Buffer = command.Dump.Buffer;
    crash.CrashDumpHeader.Size = command.Dump.Size;

    onUserModeCrash.emit(state, crash);

    vmi::windows::BugCheckDescription info;
    info.guestHeader = crash.CrashDumpHeader.Buffer;
    info.headerSize = crash.CrashDumpHeader.Size;
    generateCrashDump(state, &info, true);

    if (m_terminateOnCrash) {
        s2e()->getExecutor()->terminateStateEarly(*state, "User mode crash");
    }
}

void BugCollector::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_BUG_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_BUG_COMMAND size\n";
        return;
    }

    if (!state->mem()->readMemoryConcrete(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        case WINDOWS_USERMODE_CRASH: {
            opUserModeCrash(state, guestDataPtr, command);
        } break;

        default: { getWarningsStream(state) << "Unknown command\n"; } break;
    }
}

} // namespace plugins
} // namespace s2e
