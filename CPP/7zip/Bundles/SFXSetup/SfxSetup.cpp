// Main.cpp

#include "StdAfx.h"
#include "../../../../C/DllSecur.h"
#include "../../../Common/MyWindows.h"
#include "../../../Common/MyInitGuid.h"
#include "../../../Common/CommandLineParser.h"
#include "../../../Common/StringConvert.h"
#include "../../../Common/TextConfig.h"
#include "../../../Windows/DLL.h"
#include "../../../Windows/ErrorMsg.h"
#include "../../../Windows/FileDir.h"
#include "../../../Windows/FileFind.h"
#include "../../../Windows/FileIO.h"
#include "../../../Windows/FileName.h"
#include "../../../Windows/NtCheck.h"
#include "../../../Windows/ResourceString.h"
#include "../../UI/Explorer/MyMessages.h"
#include "ExtractEngine.h"
#include "resource.h"
#include <stdio.h>
#include <iostream>
#include <tchar.h>
#include <conio.h>

using namespace NWindows;
using namespace NFile;
using namespace NDir;

extern HINSTANCE g_hInstance;
HINSTANCE g_hInstance;
extern bool g_DisableUserQuestions;
bool g_DisableUserQuestions;

static CFSTR const kTempDirPrefix = FTEXT("7zS");

// #define _UNICODE
#define MY_SHELL_EXECUTE

static bool ReadDataString(CFSTR fileName, LPCSTR startID, LPCSTR endID,
                           AString &stringResult) {
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
      } else {
        if (pos + signatureStartSize > numBytesInBuffer) break;
        if (memcmp(buffer + pos, startID, signatureStartSize) == 0) {
          writeMode = true;
          pos += signatureStartSize;
        } else
          pos++;
      }
    }
    numBytesPrev = numBytesInBuffer - pos;
    posTotal += pos;
    memmove(buffer, buffer + pos, numBytesPrev);
  }
}

static char kStartID[] = {',', '!', '@', 'I', 'n', 's', 't', 'a', 'l', 'l',
                          '@', '!', 'U', 'T', 'F', '-', '8', '!', 0};
static char kEndID[] = {',', '!', '@', 'I', 'n', 's', 't', 'a',
                        'l', 'l', 'E', 'n', 'd', '@', '!', 0};

static struct CInstallIDInit {
  CInstallIDInit() {
    kStartID[0] = ';';
    kEndID[0] = ';';
  }
} g_CInstallIDInit;

#if defined(_WIN32) && defined(_UNICODE) && !defined(_WIN64) && \
    !defined(UNDER_CE)
#define NT_CHECK_FAIL_ACTION                        \
  ShowErrorMessage(L"Unsupported Windows version"); \
  return 1;
#endif

static void ShowErrorMessageSpec(const UString &name) {
  UString message = NError::MyFormatMessage(::GetLastError());
  const int pos = message.Find(L"%1");
  if (pos >= 0) {
    message.Delete((unsigned)pos, 2);
    message.Insert((unsigned)pos, name);
  }
  ShowErrorMessage(NULL, message);
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE /* hPrevInstance */,
#ifdef UNDER_CE
                     LPWSTR
#else
                     LPSTR
#endif
                     /* lpCmdLine */,
                     int /* nCmdShow */) {
  g_hInstance = (HINSTANCE)hInstance;

  NT_CHECK

#ifdef _WIN32
  LoadSecurityDlls();
#endif


  // InitCommonControls();

  UString archiveName, switches;
#ifdef MY_SHELL_EXECUTE
  UString executeFile, executeParameters;
#endif
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
    if (!assumeYes) ShowErrorMessage(L"Can't load config info");
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

  FILE *fDummy;
  HANDLE hConOut;
  HANDLE hConErr;
  HANDLE hConIn;
  HANDLE hRead;
  HANDLE hWrite;

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
      if (!assumeYes) ShowErrorMessage(L"Config failed");
      return 1;
    }
    const UString cfgRunAs = GetTextConfigValue(pairs, "DoElevate");
    const UString cfgConsole = GetTextConfigValue(pairs, "DoConsole");
    const UString cfgConsoleWait = GetTextConfigValue(pairs, "DoConsoleWait");
    const UString friendlyName = GetTextConfigValue(pairs, "Title");
    const UString installPrompt = GetTextConfigValue(pairs, "BeginPrompt");
    const UString progress = GetTextConfigValue(pairs, "ShowProgress");

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
      } else {
        return dwError;
      }
      hProcess = execInfo.hProcess;
      WaitForSingleObject(hProcess, INFINITE);
      ::CloseHandle(hProcess);
      return 0;
    }
    if (cfgConsole.IsEqualTo_Ascii_NoCase("true")) doConsole = true;
    if (cfgConsoleWait.IsEqualTo_Ascii_NoCase("true")) doConsoleWait = true;
    if (doConsole || doConsoleWait) {
      AllocConsole();
      // This does not work as expected, makes console unusable.
      //if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        
        //AttachConsole(GetCurrentProcessId());
        //HWND Handle = GetConsoleWindow();
      //}
      FILE* fp;
      bool result = true;
      // Redirect STDIN if the console has an input handle
      if (GetStdHandle(STD_INPUT_HANDLE) != INVALID_HANDLE_VALUE) {
        if (freopen_s(&fp, "CONIN$", "r", stdin) != 0) {
          result = false;
        }
        else {
          setvbuf(stdin, NULL, _IONBF, 0);
        }
      }
      // Redirect STDOUT if the console has an output handle
      if (GetStdHandle(STD_OUTPUT_HANDLE) != INVALID_HANDLE_VALUE) {
        if (freopen_s(&fp, "CONOUT$", "w", stdout) != 0) {
          result = false;
        } else {
          setvbuf(stdout, NULL, _IONBF, 0);
        }
      }
      // Redirect STDERR if the console has an error handle
      if (GetStdHandle(STD_ERROR_HANDLE) != INVALID_HANDLE_VALUE) {
        if (freopen_s(&fp, "CONOUT$", "w", stderr) != 0) {
          result = false;
        } else {
          setvbuf(stderr, NULL, _IONBF, 0);
        }
      }
      std::ios::sync_with_stdio(true);
      hConOut = CreateFile(_T("CONOUT$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
      std::wcout.clear();
      std::cout.clear();
      std::wcerr.clear();
      std::cerr.clear();
      std::wcin.clear();
      std::cin.clear();
    }
    ::CloseHandle(hMyProcess);
    if (progress.IsEqualTo_Ascii_NoCase("false")) showProgress = false;
    const int index = FindTextConfigItem(pairs, "Directory");
    if (index >= 0) dirPrefix = pairs[index].String;
    if (!installPrompt.IsEmpty() && !assumeYes) {
      if (MessageBoxW(NULL, installPrompt, friendlyName, MB_YESNO | MB_ICONQUESTION) != IDYES)
        return 2;
    }
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
      if (!assumeYes) ShowErrorMessage(L"Cannot create temp folder archive");
      return 1;
    }
    FinstallPath = tempDir.GetPath();
  }

  CCodecs *codecs = new CCodecs;
  CMyComPtr<IUnknown> compressCodecsInfo = codecs;
  {
    const HRESULT result = codecs->Load();
    if (result != S_OK) {
      ShowErrorMessage(L"Cannot load codecs");
      return 1;
    }
  }

  // const FString tempDirPath = tempDir.GetPath();
  //  tempDirPath = L"M:\\1\\"; // to test low disk space
  {
    bool isCorrupt = false;
    UString errorMessage;
    HRESULT result = ExtractArchive(codecs, fullPath, FinstallPath,
                                    showProgress, isCorrupt, errorMessage);

    if (result != S_OK) {
      if (!assumeYes) {
        if (result == S_FALSE || isCorrupt) {
          NWindows::MyLoadString(IDS_EXTRACTION_ERROR_MESSAGE, errorMessage);
          result = E_FAIL;
        }
        if (result != E_ABORT) {
          if (errorMessage.IsEmpty())
            errorMessage = NError::MyFormatMessage(result);
          ::MessageBoxW(NULL, errorMessage,
                        NWindows::MyLoadString(IDS_EXTRACTION_ERROR_TITLE),
                        MB_SETFOREGROUND | MB_ICONERROR);
        }
      }
      return 1;
    }
  }

#ifndef UNDER_CE
  CCurrentDirRestorer currentDirRestorer;
  if (!SetCurrentDir(FinstallPath)) return 1;
#endif

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
      if (!assumeYes) ShowErrorMessage(L"Cannot find executable!");
      if (!assumeYes) ShowErrorMessage(appLaunchedSys);
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
      if (!assumeYes) {
        // we print name of exe file, if error message is
        // ERROR_BAD_EXE_FORMAT: "%1 is not a valid Win32 application".
        ShowErrorMessageSpec(appNameForError);
      }
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
  if (doConsole||doConsoleWait) {
    FreeConsole();
  }
  return 0;
}
