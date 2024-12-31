// Main.cpp

#include "StdAfx.h"

#include "../../../../C/CpuArch.h"
#include "../../../../C/DllSecur.h"

#include "../../../Common/MyWindows.h"
#include "../../../Common/MyInitGuid.h"

#include "../../../Common/CommandLineParser.h"
#include "../../../Common/MyException.h"

#ifdef _WIN32
#include "../../../Windows/DLL.h"
#else
#include "../../../Common/StringConvert.h"
#endif
#include "../../../Windows/FileDir.h"
#include "../../../Windows/FileName.h"

#include "../../UI/Common/ExitCode.h"
#include "../../UI/Common/Extract.h"

#include "../../UI/Console/ExtractCallbackConsole.h"
#include "../../UI/Console/List.h"
#include "../../UI/Console/OpenCallbackConsole.h"
#include "../../../Common/StringConvert.h"
#include "../../../Common/TextConfig.h"

#include "../../MyVersion.h"
#include <stdio.h>
#include <iostream>
#include <tchar.h>
#include <conio.h>


using namespace NWindows;
using namespace NFile;
using namespace NDir;
using namespace NCommandLineParser;

static CFSTR const kTempDirPrefix = FTEXT("7zC");

#ifdef _WIN32
extern
HINSTANCE g_hInstance;
HINSTANCE g_hInstance = NULL;
#endif
extern
int g_CodePage;
int g_CodePage = -1;
extern CStdOutStream *g_StdStream;

static const char * const kCopyrightString = "\n7-Zip InfinitySFX " MY_VERSION_CPU " https://github.com/BiatuAutMiahn/7zip\n";

namespace NKey {
enum Enum
{
  kHelp1 = 0,
  kHelp2,
  kDisablePercents,
  kYes,
  kPassword,
  kOutputDir
};

}

namespace NRecursedType {
enum EEnum
{
  kRecursed,
  kWildcardOnlyRecursed,
  kNonRecursed
};
}
/*
static const char kRecursedIDChar = 'R';

namespace NRecursedPostCharIndex {
  enum EEnum
  {
    kWildcardRecursionOnly = 0,
    kNoRecursion = 1
  };
}

static const char kFileListID = '@';
static const char kImmediateNameID = '!';

static const char kSomeCludePostStringMinSize = 2; // at least <@|!><N>ame must be
static const char kSomeCludeAfterRecursedPostStringMinSize = 2; // at least <@|!><N>ame must be
*/

#define SWFRM_3(t, mu, mi) t, mu, mi, NULL
#define SWFRM_1(t)     SWFRM_3(t, false, 0)
#define SWFRM_SIMPLE   SWFRM_1(NSwitchType::kSimple)
#define SWFRM_STRING_SINGL(mi) SWFRM_3(NSwitchType::kString, false, mi)

static const int kNumCommandForms = 3;

static const NRecursedType::EEnum kCommandRecursedDefault[kNumCommandForms] =
{
  NRecursedType::kRecursed
};

// static const bool kTestExtractRecursedDefault = true;
// static const bool kAddRecursedDefault = false;

static const char * const kUniversalWildcard = "*";

static const char * const kHelpString =
    "\nUsage: 7zSFX [<command>] [<switches>...] [<file_name>...]\n"
    "\n"
    "<Commands>\n"
    // "  l: List contents of archive\n"
    "  t: Test integrity of archive\n"
    "  x: eXtract files with full pathname (default)\n"
    "<Switches>\n"
    // "  -bd Disable percentage indicator\n"
    "  -o{Directory}: set Output directory\n"
    "  -p{Password}: set Password\n"
    "  -y: assume Yes on all queries\n";


// ---------------------------
// exception messages

static const char * const kUserErrorMessage  = "Incorrect command line"; // NExitCode::kUserError
// static const char * const kIncorrectListFile = "Incorrect wildcard in listfile";
static const char * const kIncorrectWildcardInCommandLine  = "Incorrect wildcard in command line";

// static const CSysString kFileIsNotArchiveMessageBefore = "File \"";
// static const CSysString kFileIsNotArchiveMessageAfter = "\" is not archive";

// static const char * const kProcessArchiveMessage = " archive: ";

static const char * const kCantFindSFX = " cannot find sfx";

namespace NCommandType
{
  enum EEnum
  {
    kTest = 0,
    kFullExtract,
    kList
  };
}

static const char *g_Commands = "txl";

struct CArchiveCommand
{
  NCommandType::EEnum CommandType;

  NRecursedType::EEnum DefaultRecursedType() const;
};

static bool ParseArchiveCommand(const UString &commandString, CArchiveCommand &command)
{
  UString s = commandString;
  s.MakeLower_Ascii();
  if (s.Len() != 1)
    return false;
  if (s[0] >= 0x80)
    return false;
  int index = FindCharPosInString(g_Commands, (char)s[0]);
  if (index < 0)
    return false;
  command.CommandType = (NCommandType::EEnum)index;
  return true;
}

NRecursedType::EEnum CArchiveCommand::DefaultRecursedType() const
{
  return kCommandRecursedDefault[CommandType];
}

static void PrintHelp(void)
{
  g_StdOut << kHelpString;
}

Z7_ATTR_NORETURN
static void ShowMessageAndThrowException(const char *message, NExitCode::EEnum code)
{
  g_StdOut << message << endl;
  throw code;
}

Z7_ATTR_NORETURN
static void PrintHelpAndExit() // yyy
{
  PrintHelp();
  ShowMessageAndThrowException(kUserErrorMessage, NExitCode::kUserError);
}

// ------------------------------------------------------------------
// filenames functions

static bool AddNameToCensor(NWildcard::CCensor &wildcardCensor,
    const UString &name, bool include, NRecursedType::EEnum type)
{
  /*
  if (!IsWildcardFilePathLegal(name))
    return false;
  */
  const bool isWildcard = DoesNameContainWildcard(name);
  bool recursed = false;

  switch (type)
  {
    case NRecursedType::kWildcardOnlyRecursed:
      recursed = isWildcard;
      break;
    case NRecursedType::kRecursed:
      recursed = true;
      break;
    case NRecursedType::kNonRecursed:
      recursed = false;
      break;
  }

  NWildcard::CCensorPathProps props;
  props.Recursive = recursed;
  wildcardCensor.AddPreItem(include, name, props);
  return true;
}

static void AddCommandLineWildcardToCensor(NWildcard::CCensor &wildcardCensor,
    const UString &name, bool include, NRecursedType::EEnum type)
{
  if (!AddNameToCensor(wildcardCensor, name, include, type))
    ShowMessageAndThrowException(kIncorrectWildcardInCommandLine, NExitCode::kUserError);
}


#ifndef _WIN32
static void GetArguments(int numArgs, char *args[], UStringVector &parts)
{
  parts.Clear();
  for (int i = 0; i < numArgs; i++)
  {
    UString s = MultiByteToUnicodeString(args[i]);
    parts.Add(s);
  }
}
#endif


static bool ReadDataString(CFSTR fileName, LPCSTR startID, LPCSTR endID,
  AString& stringResult) {
  stringResult.Empty();
  NIO::CInFile inFile;
  if (!inFile.Open(fileName)) return false;
  const size_t kBufferSize = (1 << 12);

  Byte buffer[kBufferSize];
  const unsigned signatureStartSize = MyStringLen(startID);
  const unsigned signatureEndSize = MyStringLen(endID);

  size_t numBytesPrev = 0;
  bool writeMode = false;
  UInt64 posTotal = 0;

  for (;;) {
    if (posTotal > (1 << 22)) return (stringResult.IsEmpty());
    const size_t numReadBytes = kBufferSize - numBytesPrev;
    size_t processedSize;
    if (!inFile.ReadFull(buffer + numBytesPrev, numReadBytes, processedSize))
      return false;
    if (processedSize == 0) return true;
    const size_t numBytesInBuffer = numBytesPrev + processedSize;
    UInt32 pos = 0;
    for (;;) {
      if (writeMode) {
        if (pos + signatureEndSize > numBytesInBuffer) break;
        if (memcmp(buffer + pos, endID, signatureEndSize) == 0) return true;
        const Byte b = buffer[pos];
        if (b == 0) return false;
        stringResult += (char)b;
        pos++;
      }
      else {
        if (pos + signatureStartSize > numBytesInBuffer) break;
        if (memcmp(buffer + pos, startID, signatureStartSize) == 0) {
          writeMode = true;
          pos += signatureStartSize;
        }
        else
          pos++;
      }
    }
    numBytesPrev = numBytesInBuffer - pos;
    posTotal += pos;
    memmove(buffer, buffer + pos, numBytesPrev);
  }
}

static char kStartID[] = { ',', '!', '@', 'I', 'n', 's', 't', 'a', 'l', 'l',
                          '@', '!', 'U', 'T', 'F', '-', '8', '!', 0 };
static char kEndID[] = { ',', '!', '@', 'I', 'n', 's', 't', 'a',
                        'l', 'l', 'E', 'n', 'd', '@', '!', 0 };

static struct CInstallIDInit {
  CInstallIDInit() {
    kStartID[0] = ';';
    kEndID[0] = ';';
  }
} g_CInstallIDInit;


int Main2();
int Main2()
{
  // do we need load Security DLLs for console program?
  LoadSecurityDlls();

  SetFileApisToOEM();
  
  #ifdef ENV_HAVE_LOCALE
  MY_SetLocale();
  #endif

  g_StdOut << kCopyrightString;
  
  UString archiveName, switches;
  UString executeFile, executeParameters;
  UStringVector commandStrings;
  NCommandLineParser::SplitCommandLine(GetCommandLineW(), commandStrings);

  NCommandLineParser::SplitCommandLine(GetCommandLineW(), archiveName,
    switches);

  FString fullPath;
  NDLL::MyGetModuleFileName(fullPath);

  switches.Trim();
  bool assumeYes = false;
  if (switches.IsPrefixedBy_Ascii_NoCase("-y")) {
    assumeYes = true;
    switches = switches.Ptr(2);
    switches.Trim();
  }


  AString config;
  if (!ReadDataString(fullPath, kStartID, kEndID, config)) {
    (*g_StdStream) << endl << L"Can't load config info" << endl;
    return 1;
  }


  UString dirPrefix("." STRING_PATH_SEPARATOR);
  UString appLaunched;
  UString configInstallPath;
  UString installPath;
  FString FinstallPath;
  LPWSTR lpwsInstallPath;
  bool isElevated = false;
  bool showProgress = true;
  bool runWait = true;
  bool doRunAs = false;
  bool doCleanup = true;
  bool doConsole = false;
  bool doConsoleWait = false;

  // Check if elevated.
  HANDLE hToken = NULL;
  HANDLE hMyProcess = GetCurrentProcess();
  DWORD hMyPid = GetProcessId(NULL);
  if (OpenProcessToken(hMyProcess, TOKEN_QUERY, &hToken)) {
    TOKEN_ELEVATION elevation;
    DWORD dwSize = sizeof(TOKEN_ELEVATION);
    if (GetTokenInformation(hToken, TokenElevation, &elevation,
      sizeof(elevation), &dwSize)) {
      isElevated = elevation.TokenIsElevated;
    }
    CloseHandle(hToken);
  }


  if (!config.IsEmpty()) {
    CObjectVector<CTextConfigPair> pairs;
    if (!GetTextConfig(config, pairs)) {
      (*g_StdStream) << endl << L"Config failed" << endl;
      return 1;
    }
    const UString cfgRunAs = GetTextConfigValue(pairs, "DoElevate");
    const UString cfgConsoleWait = GetTextConfigValue(pairs, "DoConsoleWait");

    if (!isElevated && cfgRunAs.IsEqualTo_Ascii_NoCase("true")) {
      HANDLE hProcess = NULL;
      CSysString filePath(GetSystemString(fullPath));
      SHELLEXECUTEINFO execInfo;
      execInfo.cbSize = sizeof(execInfo);
      execInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
      execInfo.hwnd = NULL;
      execInfo.lpVerb = L"runas";
      execInfo.lpFile = filePath;
      executeParameters.Add_Space_if_NotEmpty();
      executeParameters += switches;
      LPWSTR lpwsParametersSys;
      const CSysString parametersSys(GetSystemString(executeParameters));
      if (parametersSys.IsEmpty()) {
        execInfo.lpParameters = NULL;
      }
      else {
        execInfo.lpParameters = parametersSys;
      }
      execInfo.lpDirectory = dirPrefix;
      execInfo.nShow = SW_SHOWNORMAL;
      execInfo.hProcess = NULL;
      ::ShellExecuteEx(&execInfo);
      DWORD dwError = GetLastError();
      if (dwError == ERROR_CANCELLED) {
        //User refused to allow elevation.
        return 2;
      }
      else {
        return dwError;
      }
      hProcess = execInfo.hProcess;
      WaitForSingleObject(hProcess, INFINITE);
      ::CloseHandle(hProcess);
      return 0;
    }
    doConsole = true;
    if (cfgConsoleWait.IsEqualTo_Ascii_NoCase("true")) doConsoleWait = true;
    //if (doConsole || doConsoleWait) {
      //AllocConsole();
      // This does not work as expected, makes console unusable.
      //if (!AttachConsole(ATTACH_PARENT_PROCESS)) {

        //AttachConsole(GetCurrentProcessId());
        //HWND Handle = GetConsoleWindow();
      //}
      //FILE* fp;
      //bool result = true;
      // Redirect STDIN if the console has an input handle
      //if (GetStdHandle(STD_INPUT_HANDLE) != INVALID_HANDLE_VALUE) {
      //  if (freopen_s(&fp, "CONIN$", "r", stdin) != 0) {
      //    result = false;
      //  }
      //  else {
      //    setvbuf(stdin, NULL, _IONBF, 0);
      //  }
      //}
      //// Redirect STDOUT if the console has an output handle
      //if (GetStdHandle(STD_OUTPUT_HANDLE) != INVALID_HANDLE_VALUE) {
      //  if (freopen_s(&fp, "CONOUT$", "w", stdout) != 0) {
      //    result = false;
      //  }
      //  else {
      //    setvbuf(stdout, NULL, _IONBF, 0);
      //  }
      //}
      //// Redirect STDERR if the console has an error handle
      //if (GetStdHandle(STD_ERROR_HANDLE) != INVALID_HANDLE_VALUE) {
      //  if (freopen_s(&fp, "CONOUT$", "w", stderr) != 0) {
      //    result = false;
      //  }
      //  else {
      //    setvbuf(stderr, NULL, _IONBF, 0);
      //  }
      //}
      //std::ios::sync_with_stdio(true);
      //hConOut = CreateFile(_T("CONOUT$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      //SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
      //std::wcout.clear();
      //std::cout.clear();
      //std::wcerr.clear();
      //std::cerr.clear();
      //std::wcin.clear();
      //std::cin.clear();
    //}
    ::CloseHandle(hMyProcess);
    //if (progress.IsEqualTo_Ascii_NoCase("false")) showProgress = false;
    const int index = FindTextConfigItem(pairs, "Directory");
    if (index >= 0) dirPrefix = pairs[index].String;
    //if (!installPrompt.IsEmpty() && !assumeYes) {
    //  if (MessageBoxW(NULL, installPrompt, friendlyName, MB_YESNO | MB_ICONQUESTION) != IDYES)
    //    return 2;
    //}
    configInstallPath = GetTextConfigValue(pairs, "InstallPath");
    lpwsInstallPath = new WCHAR[MAX_PATH + 1];
    ExpandEnvironmentStringsW(us2fs(configInstallPath).Ptr(), lpwsInstallPath, MAX_PATH + 1);
    installPath = lpwsInstallPath;
    FinstallPath = us2fs(installPath);
    //appLaunched = GetTextConfigValue(pairs, "RunProgram");
    executeFile = GetTextConfigValue(pairs, "ExecuteFile");
    executeParameters = GetTextConfigValue(pairs, "ExecuteParameters");
  }
  CTempDir tempDir;
  if (installPath.IsEmpty()) {
    if (!tempDir.Create(kTempDirPrefix)) {
      (*g_StdStream) << endl << L"Cannot create temp folder archive" << endl;
      return 1;
    }
    FinstallPath = tempDir.GetPath();
  }

  //FString arcPath;
  //{
  //  FString path;
  //  NDLL::MyGetModuleFileName(path);
  //  if (!MyGetFullPathName(path, arcPath))
  //  {
  //    g_StdOut << "GetFullPathName Error";
  //    return NExitCode::kFatalError;
  //  }
  //}

  CArchiveCommand command;
  command.CommandType = NCommandType::kFullExtract;
  NRecursedType::EEnum recursedType;
  recursedType = command.DefaultRecursedType();
  const bool yesToAll = true;
  const bool passwordEnabled = false;

  FString outputDir;
  
  UStringVector v1, v2;
  v1.Add(fs2us(fullPath));
  v2.Add(fs2us(fullPath));
  CCodecs *codecs = new CCodecs;
  CMyComPtr<
    #ifdef Z7_EXTERNAL_CODECS
    ICompressCodecsInfo
    #else
    IUnknown
    #endif
    > compressCodecsInfo = codecs;
  {
    HRESULT result = codecs->Load();
    if (result != S_OK)
      throw CSystemException(result);
  }

  CExtractCallbackConsole *ecs = new CExtractCallbackConsole;
  CMyComPtr<IFolderArchiveExtractCallback> extractCallback = ecs;
  ecs->Init(g_StdStream, &g_StdErr, g_StdStream, false);

  #ifndef Z7_NO_CRYPTO
  ecs->PasswordIsDefined = passwordEnabled;
  //ecs->Password = password;
  #endif

  /*
  COpenCallbackConsole openCallback;
  openCallback.Init(g_StdStream, g_StdStream);

  #ifndef Z7_NO_CRYPTO
  openCallback.PasswordIsDefined = passwordEnabled;
  openCallback.Password = password;
  #endif
  */
  NWildcard::CCensorNode wildcardCensor;
  wildcardCensor.Add_Wildcard();

  CExtractOptions eo;
  eo.StdOutMode = false;
  eo.YesToAll = true;
  eo.TestMode = false;//command.CommandType == NCommandType::kTest;
  eo.PathMode = NExtract::NPathMode::kFullPaths;
  eo.OverwriteMode = NExtract::NOverwriteMode::kOverwrite;//yesToAll ?
      //NExtract::NOverwriteMode::kOverwrite :
      //NExtract::NOverwriteMode::kAsk;
  eo.OutputDir = FinstallPath;

    UString errorMessage;
    CDecompressStat stat;
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    bool bNoSep = false;
    int consoleWidth;
    if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
    {
      bNoSep = true;
    } else {
      consoleWidth = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    }
    
    for (int i = 0; i < consoleWidth; ++i) {
      std::cout << '-';
    }
    std::cout << std::endl;

    HRESULT result = Extract(
        codecs, CObjectVector<COpenType>(), CIntVector(),
        v1, v2,
        wildcardCensor,
        eo,
        ecs, ecs, ecs,
        // NULL, // hash
        errorMessage, stat);

    ecs->ClosePercents();

    if (!errorMessage.IsEmpty())
    {
      (*g_StdStream) << endl << "Error: " << errorMessage;
      if (result == S_OK)
        result = E_FAIL;
    }

    if (   0 != ecs->NumCantOpenArcs
        || 0 != ecs->NumArcsWithError
        || 0 != ecs->NumFileErrors
        || 0 != ecs->NumOpenArcErrors)
    {
      if (ecs->NumCantOpenArcs != 0)
        (*g_StdStream) << endl << "Can't open as archive" << endl;
      if (ecs->NumArcsWithError != 0)
        (*g_StdStream) << endl << "Archive Errors" << endl;
      if (ecs->NumFileErrors != 0)
        (*g_StdStream) << endl << "Sub items Errors: " << ecs->NumFileErrors << endl;
      if (ecs->NumOpenArcErrors != 0)
        (*g_StdStream) << endl << "Open Errors: " << ecs->NumOpenArcErrors << endl;
      return NExitCode::kFatalError;
    }
    for (int i = 0; i < consoleWidth; ++i) {
      std::cout << '-';
    }
    std::cout << std::endl;
    CCurrentDirRestorer currentDirRestorer;
    if (!SetCurrentDir(FinstallPath)) return 1;

    if (result != S_OK)
      throw CSystemException(result);

    HANDLE hProcess = NULL;
    PROCESS_INFORMATION processInformation;
    if (!executeFile.IsEmpty()) {
      // appLaunched = L"setup.exe";

      LPWSTR lpwsAppLaunchedSys;
      lpwsAppLaunchedSys = new WCHAR[MAX_PATH + 1];
      ExpandEnvironmentStrings(executeFile, lpwsAppLaunchedSys, MAX_PATH + 1);
      const CSysString appLaunchedSys(
        GetSystemString(/*dirPrefix + */lpwsAppLaunchedSys));

      if (!NFind::DoesFileExist_FollowLink(us2fs(appLaunchedSys))) {
        wprintf(L"Cannot find executable!\r\n"+ executeFile +L"\r\n");
        return 1;
      }
      executeFile = us2fs(appLaunchedSys);
      {
        FString s2 = installPath;
        NName::NormalizeDirPathPrefix(s2);
        executeFile.Replace(L"%%T" WSTRING_PATH_SEPARATOR, fs2us(s2));
      }

      const UString appNameForError =
        executeFile;  // actually we need to rtemove parameters also

      executeFile.Replace(L"%%T", fs2us(installPath));

      if (!executeParameters.IsEmpty()) {
        executeFile.Add_Space();
        executeFile += executeParameters;
      }

      if (!switches.IsEmpty()) {
        executeFile.Add_Space();
        executeFile += switches;
      }

      STARTUPINFO startupInfo;
      ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
      startupInfo.cb = sizeof(STARTUPINFO);
      startupInfo.lpReserved = NULL;
      startupInfo.lpDesktop = NULL;
      startupInfo.lpTitle = NULL;
      startupInfo.dwFlags = 0;
      startupInfo.cbReserved2 = 0;
      startupInfo.lpReserved2 = NULL;

      PROCESS_INFORMATION processInformation;


      const BOOL createResult = CreateProcess(
        NULL, executeFile.Ptr_non_const(), NULL, NULL, FALSE, 0, NULL,
        NULL /*tempDir.GetPath() */, &startupInfo, &processInformation);
      if (createResult == 0) {
        wprintf(appNameForError+L"\r\n");
        return 1;
      }
      ::CloseHandle(processInformation.hThread);
      hProcess = processInformation.hProcess;
    }

    if (hProcess) {
      WaitForSingleObject(hProcess, INFINITE);
      ::CloseHandle(hProcess);
    }

    if (doConsoleWait) {
      wprintf(L"\r\nPress any key to exit...");
      _getch();  // Wait for key press before exiting
    }
    if (doConsole || doConsoleWait) {
      FreeConsole();
    }
  return 0;
}
