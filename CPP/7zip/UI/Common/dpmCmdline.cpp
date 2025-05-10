#include "StdAfx.h"
#include "dpmCmdline.h"

bool CArcCommandDpm::IsFromDpmGroup() const {
    switch((int)CommandType) {
        case NCommandTypeDpm::kDpm:
            return true;
        default:
            return false;
    }
}

// create archive
// -IsMatching
// -IsUpdate
//
// (-DoExtract ^ ((-DoUpdate  ^ -DoInstall) [-UnSafe]))
// (-mkArchive ^ (-mkSFX [-WinPE])) [-NotSolid]
//
// -IsUpdate (Perform action on drivers that are newer)
// -IsMatching (Perform action on any match)
// -DoExtract (Extract Drivers)
// -DoUpdate (Install/Update Drivers)
// -DoInstall (Install Drivers, Do not check if devices are present)
// -WinPE [-DoDrvLoad] (Force creation of SFX that only functions under WinPE,
// extract and install/update) -UnSafe [-AcceptRisk] (Parse Inf, perform manual
// install)
