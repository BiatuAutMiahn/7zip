#pragma once
#include "../../../Common/CommandLineParser.h"
#include "ArchiveCommandLine.h"

namespace NCommandTypeDpm {
    enum EEnum {
        kAdd        = NCommandType::kAdd,
        kUpdate     = NCommandType::kUpdate,
        kDelete     = NCommandType::kDelete,
        kTest       = NCommandType::kTest,
        kExtract    = NCommandType::kExtract,
        kExtractFull= NCommandType::kExtractFull,
        kList       = NCommandType::kList,
        kBenchmark  = NCommandType::kBenchmark,
        kInfo       = NCommandType::kInfo,
        kHash       = NCommandType::kHash,
        kRename     = NCommandType::kRename,
        kDpm        = NCommandType::kRename + 1
    };
}
struct CArcCommandDpm: public CArcCommand {
    NCommandTypeDpm::EEnum CommandType;
    bool                   IsFromDpmGroup() const;
};
struct CArcCmdLineOptionsDpm: public CArcCmdLineOptions {
    bool dpmUpdate;              // (Default:True) Only Match Updated drivers, otherwise match
                                 // any.
    bool          dpmHostArch;   // (Default:True) Only Match Host Arch.
    bool          dpmInstall;    // Install Matches
    bool          dpmBlind;      // Install regaurdless of device presence.
    bool          dpmPrompt;     // Prompt before any Action.
    bool          dpmExtract;    // (Default:True) Extract Matches
    bool          dpmDrvLoad;    // WinPE Only, use drvload instead of install.
    bool          dpmDPUpdate;   // (Default:True) Check, Download/Update DriverPacks.
    bool          dpmBundle;     // Bundle Matches
    bool          dpmSfx;        // Generate SFX
    bool          dpmExport;     // Export Host Profile
    bool          dpmImport;     // Import Host Profile
    bool          dpmBundleDPDB; // Rebuild DP + Embed DPDB
    UStringVector dpmHwid;       // Match delimited string of HWIDs
    UStringVector dpmArch;       // Match delimited string of Architectures;
    UStringVector dpmExclArch;   // Exclusionary Match delimited string of Architectures;
    UStringVector dpmDPParse;    // (Default:True) Parse DriverPack and Generate DPDB
    CArcCmdLineOptionsDpm():
        CArcCmdLineOptions(), dpmUpdate(true), dpmHostArch(true), dpmDPUpdate(true), dpmDrvLoad(false), dpmExport(false), dpmImport(false), dpmSfx(false), dpmPrompt(true), dpmInstall(true),
        dpmExtract(true), dpmBundle(false), dpmBlind(false), dpmBundleDPDB(false) {}
};
