#pragma once
#include "StdAfx.h"

#include <codecvt>
#include <locale>
#include <regex>
#include <string>
#include <vector>
#include <atomic>
#include <memory>
#include <chrono> 

#include "../../Common/MyWindows.h" // For Z7_*, UINT32, etc. Must be very early.
#include "../../Common/Common0.h"   // Defines Z7_FINAL, Z7_override, etc.
#include "../../Common/MyCom.h"     // For CMyUnknownImp, CMyComPtr
#include "../IDecl.h"               // Defines Z7_COM7F_IMF, Z7_IFACE_*, etc.

#include "../../Common/MyString.h"     // For UString, FString, AString
#include "../../Windows/PropVariant.h" // For NCOM::CPropVariant
#include "../Archive/IArchive.h"       // For IInArchive, IArchiveExtractCallback, kpid*
#include "../IPassword.h"              // For ICryptoGetTextPassword
#include "../Common/FileStreams.h"     // For CInFileStream, kEmptyFileAlias
#include "../Common/StreamObjects.h" // If you use CBufInStream etc.
#include "../UI/Common/PropIDUtils.h"    // For kpid* definitions
#include "../../Windows/PropVariantConv.h" // For ConvertPropVariantToUInt64
#include "../../Common/StringConvert.h"    // For StringToBstr, us2fs, fs2us, GetUnicodeString
#include "../../Windows/DLL.h"          // For NDLL::CLibrary, Func_CreateObject
#include "../../Common/IntToString.h"

#include "../../Common/Defs.h" 



#include "../UI/Common/ArchiveExtractCallback.h"
#define CURL_STATICLIB
#include "curl/curl.h"

using namespace NWindows;
//using namespace NFile;
//using namespace NDir;

CURL* dpmCurl;
CURLcode dpmCurlResp;
std::string dpmCurlRet;
std::locale dpmLoc;


static HRESULT IsArchiveItemProp(IInArchive* archive,UInt32 index,PROPID propID,bool& result){
    NCOM::CPropVariant prop;
    RINOK(archive->GetProperty(index,propID,&prop))
        if(prop.vt==VT_BOOL)
            result=VARIANT_BOOLToBool(prop.boolVal);
        else if(prop.vt==VT_EMPTY)
            result=false;
        else
            return E_FAIL;
    return S_OK;
}

static HRESULT IsArchiveItemFolder(IInArchive* archive,UInt32 index,bool& result){
    return IsArchiveItemProp(archive,index,kpidIsDir,result);
}
static const wchar_t* const kEmptyFileAlias=L"[Content]";

const char* UTF_16_BE_BOM="\xFE\xFF";
const char* UTF_16_LE_BOM="\xFF\xFE";
const char* UTF_8_BOM="\xEF\xBB\xBF";
const char* UTF_32_BE_BOM="\x00\x00\xFE\xFF";
const char* UTF_32_LE_BOM="\xFF\xFE\x00\x00";

#define DPM_DEFINE_GUID_ARC(name, id) Z7_DEFINE_GUID(name, \
  0x23170F69, 0x40C1, 0x278A, 0x10, 0x00, 0x00, 0x01, 0x10, id, 0x00, 0x00);
DPM_DEFINE_GUID_ARC(CLSID_DpmFormat7z,7)

static const char* const kTestingString="Testing     ";
static const char* const kExtractingString="Extracting  ";
static const char* const kSkippingString="Skipping    ";
static const char* const kReadingString="Reading     ";

static const char* const kUnsupportedMethod="Unsupported Method";
static const char* const kCRCFailed="CRC Failed";
static const char* const kDataError="Data Error";
static const char* const kUnavailableData="Unavailable data";
static const char* const kUnexpectedEnd="Unexpected end of data";
static const char* const kDataAfterEnd="There are some data after the end of the payload data";
static const char* const kIsNotArc="Is not archive";
static const char* const kHeadersError="Headers Error";


std::wstring_convert<std::codecvt_utf16<wchar_t,0x10ffff,std::little_endian>,wchar_t> convu16le;

bool dpmDoUpdate=0;

// STDMETHODIMP CArchiveExtractCallbackMem::CryptoGetTextPassword(BSTR*
// password){
//     if(!PasswordIsDefined){
//       // You can ask real password here from user
//       // Password = GetPassword(OutStream);
//       // PasswordIsDefined = true;
//         PrintError("Password is not defined");
//         return E_ABORT;
//     }
//     return StringToBstr(Password,password);
// }

class tPerf{
public:
    std::chrono::steady_clock::time_point tStart;
    std::chrono::steady_clock::time_point tEnd;
    std::chrono::duration<double> tElapsed;
    double tMin;
    double tMax;
    double tAvg;
    double tSum;
    double tLast;
    uint32_t iAvg;
    std::wstring sAlias;
    void clear(){
        tElapsed=std::chrono::duration<double>(0);
        tMin=0;
        tMax=0;
        tAvg=0;
        tSum=0;
        iAvg=0;
        tLast=0;
    }
    void reset(){
        clear();
        tStart=std::chrono::high_resolution_clock::now();
    }
    void start(){ tStart=std::chrono::high_resolution_clock::now(); }
    void stat(){
        wprintf(
            L"\"%s\": "
            L"{\"tLast\":%0.4fms,\"tMin\":%0.4fms,\"tMax\":%0.4fms,\"tAvg\":%0."
            L"4fms,\"tSum\":%0.4fms,\"iAvg\":%d}\r\n",
            sAlias.c_str(),tLast,tMin,tMax,tAvg,tSum,iAvg);
    }
    void chkpt(bool doStat=false){
        tEnd=std::chrono::high_resolution_clock::now();
        tElapsed=tEnd-tStart;
        tLast=tElapsed.count()*1000;
        tSum+=tLast;
        iAvg++;
        tAvg=tSum/iAvg;
        if(tMin==0||tLast<tMin) tMin=tLast;
        if(tLast>tMax) tMax=tLast;
        if(doStat) stat();
        tStart=std::chrono::high_resolution_clock::now();
    }
    tPerf(std::wstring alias){
        clear();
        sAlias=alias;
    }
};

struct vecBuf{
    uint32_t fIndex=0;
    std::wstring fPath=L"";
    std::wstring fData=L"";
};

// DB Binary:
// Signature
struct dpdb{
    struct driver{
        struct dev{
            uint32_t hwid=0;
            uint32_t desc=0;
        };
        std::wstring fPath=L"";         // drivers\viostor\amd64
        std::wstring drvClass=L"";      // System
        std::wstring drvClassGuid=L"";  // {4d36e97d-e325-11ce-bfc1-08002be10318}
        std::wstring fName=L"";         // driver.inf
        std::wstring drvDate=L"";       // YYYY/MM/DD
        std::wstring drvVer=L"";        // 0[.0[.0[.0]]]
        std::vector<std::wstring>
            drvPlats;  // nt[Architecture][.[OSMajorVersion][.[OSMinorVersion][.[ProductType][.[SuiteMask][.[BuildNumber]]]]]
        std::vector<dev> devs;
    };
    std::wstring dbMagic=L"";
    uint8_t dbSpec=0;
    std::wstring dpFileName=L"";
    std::wstring dpBaseName=L"";
    uint16_t dpVersion=0;
    std::vector<std::wstring> dpStrings;
    std::vector<std::wstring> dpDevices;
    std::vector<driver> dpDrivers;
    dpdb(){
        dbMagic=L"inf.ddb";
        dbSpec=1;
        dpVersion=0;
    }
};

class dp{
public:
    std::wstring dpFileName=L"";
    std::wstring dpBaseName=L"";
    uint16_t dpVersion=0;
    std::vector<vecBuf> vInfs;
    dpdb dpDB;
};

struct dpStrRef{
    std::wstring sRef=L"";
    std::wstring sDef=L"";
    // uint64_t iRef;
};

LPCWSTR dpsu=L"https://download0.driverpack.io/driverpacks/";
std::vector<dp> srvDPs;
std::vector<dp> localDPs;
std::vector<dpdb> localDBs;
LPCWSTR dpsPath=L"DriverPacks";

struct vecInfSect{
    std::wstring sect=L"";
    std::vector<std::wstring> lines;
};

struct devInfo{
    struct driver{
        std::wstring dp=L"";
        std::wstring fPath=L"";         // drivers\viostor\amd64
        std::wstring fName=L"";         // driver.inf
        std::wstring drvClass=L"";      // System
        std::wstring drvClassGuid=L"";  // {4d36e97d-e325-11ce-bfc1-08002be10318}
        std::wstring drvDate=L"";       // YYYY/MM/DD
        std::wstring drvVer=L"";        // 0[.0[.0[.0]]]
        std::vector<std::wstring> hwidMatch;
        std::vector<std::wstring> drvPlats;  // nt[Architecture][.[OSMajorVersion][.[OSMinorVersion][.[ProductType][.[SuiteMask][.[BuildNumber]]]]]
    };
    std::wstring desc=L"";
    std::wstring devClass=L"";
    std::wstring devClassGuid=L"";
    driver drvLocal;
    std::vector<std::wstring> hwids;
    std::vector<std::wstring> chwids;
    std::vector<driver> drivers;
};

struct drvExtract{
    std::wstring dp=L"";
    std::vector<std::wstring> paths;
};

struct devMatch{
    // uint32_t iDev;
    std::wstring devId=L"";
    devInfo::driver driver;
    std::vector<uint32_t> iDevs;
};

static const wchar_t* const kDpmEmptyFileAlias=L"[Content]";



static std::wregex ltrim(L"^\\s+");
static std::wregex rtrim(L"\\s+$");

static std::wregex exp_chwid(
    L"^\"([^\"]*)\"\\s*$");  // Match Inf String
// static std::wregex
// exp_fnp(L"^(.*)[\\\\\/]([^\\\\\/]*\\..*)$");
static std::wregex exp_fnp(L"^(.*)[\\\\/]([^\\\\/]*\\..*)$");
static std::wregex exp_dv(
    L"^driverver\\s*=\\s*(?:(\\d{1,2}[\\/-]\\d{1,2}[\\/"
    L"-]\\d{4})|%[^%]+%)?(?:,\\s*(?:Ver\\s?)?(\\d+(?:\\.?\\d+)+|%[^%]*%)?\.?"
    L"\\s*)?(?:\\s*;.*)?$");  // Match DriverVer
static std::wregex exp_dvod(
    L"^driverver\\s*=\\s*(\\d{2}\\/\\d{2}\\/"
    L"\\d{4})\\s*(?:\\s*;.*)?$");  // Match DriverVer, only date.
static std::wregex exp_dc(L"^class\\s*=\\s*(.*)?(?:\\s*;.*)?$");  // Match Class
static std::wregex exp_dg(
    L"^classguid\\s*=\\s*(.*)?(?:\\s*;.*)?$");  // Match ClassGuid
static std::wregex exp_mfgm(
    L"^[^=]+=\\s*([^,\\s]+)(?:\\s*(?:,\\s*([^\\r\\n;]+)\\s*)+)?.*");  //(L"^(\".+\"|%[^\\s=]+%)\\s*=\\s*([^,\\s]+)(?:(?:,\\s*([^;\\r]*))+)?(?:[.\\s\\r\\n]+)?$");
////^(\".+\"|[^=]+)=([^,]+)(?:(?:,\\s*([^;]*))+)?(?:\\s*;.*)?$");
static std::wregex exp_mfgd(
    L"^(\".+\"|[^=]+)=[^,]+,\\s*(?:,\\s*)?([^;]*)(?:\\s*;.*)?$");
static std::wregex exp_saqm(
    L"^(?:\"([^=\"]+)\")\\s*=\\s*\"{1,2}?([^=\"]*)\"{1,2}?\\s*$");
static std::wregex exp_sabm(L"^(?:([^=]+))\\s*=\\s*\"*([^=\"]+)\"*\\s*$");
static std::wregex exp_sam(L"^([^=\\s]+)\\s*=\\s*(?:\"((?:[^\"]|\"\")*)\"|([^;]*?))\\s*(?:;\\s*(?:.*))?$");//^([^=\\s]+)\\s*=\\s*(?:\"((?:[^\"]|\"\")*)\"|([^\\s\"]+))\\s*$
static std::wregex exp_s(
    L"[^\\[\\]]*\\[([^\\[\\]]+)\\][^\\[\\]]*");  // Match Inf Section
static std::wregex exp_sra(
    L"\"?([^=\"]*)\"?=\"*([^=\"]+)\"*$");  // Match Inf String Ref Assignment
static std::wregex ea(
    L"^([^=]+=[^=\\r;]+)(?:[.\\r\\n]+)?.*");  //(L"((?:\\S+)|\"(?:.+)\")\\s*=\\s*((?:\\S+)|(?:(?:,\\s*)?(?:\\S+))+|\"(?:.+)\")\s*");
//// Proper Assignments
static std::wregex exp_sr(L"\\%([^\\s\\%]*)\\%\\s*");  // Match Inf String Ref
static std::wregex exp_inlsrm(L".*(%[^\\s%]+%|\"[^\"]+\").*");
static std::wregex exp_srq(L"^\"([^\"]*)\"\\s*$");  // Match Inf String Ref
static std::wregex exp_dvsm(L"^\\s*driverver\\s*=\s*.*$",
                            std::regex_constants::icase);
static std::wregex exp_dcsm(L"^ Class=.*$");
static std::wregex exp_dgsm(L"^ ClassGUID=.*$");
static std::wregex exp_inlsr(L"%[^\\s%]+%");
static std::wregex exp_slcm(L"^[\\s\\t]*;.*");
// exp_saqm
// exp_sra
// exp_sam
// exp_sabm


static void Convert_UString_to_AString(const UString& s,AString& temp){
    int codePage=CP_OEMCP;
    /*
    int g_CodePage = -1;
    int codePage = g_CodePage;
    if (codePage == -1)
      codePage = CP_OEMCP;
    if (codePage == CP_UTF8)
      ConvertUnicodeToUTF8(s, temp);
    else
    */
    UnicodeStringToMultiByte2(temp,s,(UINT)codePage);
}


static void Print(const char* s){
    fputs(s,stdout);
}

static void Print(const AString& s){
    Print(s.Ptr());
}

static void Print(const UString& s){
    AString as;
    Convert_UString_to_AString(s,as);
    Print(as);
}

static void Print(const wchar_t* s){
    Print(UString(s));
}

static void PrintNewLine(){
    Print("\n");
}

static void PrintStringLn(const char* s){
    Print(s);
    PrintNewLine();
}

static void PrintError(const char* message){
    Print("Error: ");
    PrintNewLine();
    Print(message);
    PrintNewLine();
}

static void PrintError(const char* message,const FString& name){
    PrintError(message);
    Print(name);
}


class DPM_CArchiveOpenCallback Z7_final:
    public IArchiveOpenCallback,
    public ICryptoGetTextPassword,
    public CMyUnknownImp{
    Z7_IFACES_IMP_UNK_2(IArchiveOpenCallback,ICryptoGetTextPassword)
public:

    bool PasswordIsDefined;
    UString Password;

    DPM_CArchiveOpenCallback(): PasswordIsDefined(false){}
};

Z7_COM7F_IMF(DPM_CArchiveOpenCallback::SetTotal(const UInt64* /* files */,const UInt64* /* bytes */)){
    return S_OK;
}

Z7_COM7F_IMF(DPM_CArchiveOpenCallback::SetCompleted(const UInt64* /* files */,const UInt64* /* bytes */)){
    return S_OK;
}

Z7_COM7F_IMF(DPM_CArchiveOpenCallback::CryptoGetTextPassword(BSTR* password)){
    if(!PasswordIsDefined){
        // You can ask real password here from user
#if 0
        RINOK(GetPassword_HRESULT(&g_StdOut,Password))
            PasswordIsDefined=true;
#else
        //PrintError("Password is not defined");
        return E_ABORT;
#endif
    }
    return StringToBstr(Password,password);
}

class DPM_CArchiveExtractCallbackMem Z7_final:
    public IArchiveExtractCallback,     // For archive extraction notifications
    public ICryptoGetTextPassword,    // For password handling
    public ISequentialOutStream,      // To BE the output stream for in-memory extraction
    public IProgress,                 // To handle progress notifications
    public CMyUnknownImp{
    Z7_IFACES_IMP_UNK_2(IArchiveExtractCallback,ICryptoGetTextPassword)
        Z7_IFACE_COM7_IMP(IProgress)

    CMyComPtr<IInArchive> _archiveHandler;
    const wchar_t* _fnMatch;
    std::string	file_data;
    FString _directoryPath;  // Output directory
    UString _filePath;       // name inside arcvhive
    //FString _diskFilePath;   // full path to file on disk
    bool _extractMode=false;
    UInt32 file_index;
    struct CProcessedFileInfo{
        CArcTime MTime;
        UInt32 Attrib=0;
        bool isDir=false;
        bool Attrib_Defined=false;
    } _processedFileInfo;

    //COutFileStream* _outFileStreamSpec;
    //CMyComPtr<ISequentialOutStream> _outFileStream;

public:
    void Init(IInArchive* archiveHandler,const wchar_t* fnMatch);
    // IProgress methods (can be Z7_IFACE_COM7_IMP(IProgress) or manually implemented)
    //STDMETHOD(SetTotal)(UInt64 size);
    //STDMETHOD(SetCompleted)(const UInt64* completeValue);

    // IArchiveExtractCallback methods
    //STDMETHOD(GetStream)(UInt32 index,ISequentialOutStream** outStream,Int32 askExtractMode);
    //STDMETHOD(PrepareOperation)(Int32 askExtractMode) ;
    //STDMETHOD(SetOperationResult)(Int32 resultEOperationResult);

    // ICryptoGetTextPassword method
    //STDMETHOD(CryptoGetTextPassword)(BSTR* password);

    // ISequentialOutStream method
    STDMETHOD(Write)(const void* data,UInt32 size,UInt32* processedSize);
    std::vector<vecBuf> _vBuf;
    UInt64 NumErrors=0;
    bool PasswordIsDefined;
    UString Password;
    //STDMETHOD(Write)(const void* data,UInt32 size,UInt32* processedSize){
    //    file_data.insert(file_data.length(),(const char*)data,size);
    //    if(*processedSize)
    //        *processedSize=size;
    //    return S_OK;
    //}

    void vecBufReset(vecBuf& vec){
        //std::wstring().swap(vec.fData);
        vec.fData.clear();
        vec.fData.shrink_to_fit();
        vec.fIndex=0;
        vec.fPath=std::wstring();
    }

    DPM_CArchiveExtractCallbackMem(): PasswordIsDefined(false){}
};


void getLocalDPs();
dp fName2DP(std::wstring fName);
uint8_t check_bom(const char* data,size_t size);
std::string ws2s(const std::wstring& s,int slength=0);
std::wstring s2ws(const std::string& s,int slength=0);
std::string curl_cast_url(LPCWSTR wCharString);
static size_t curl_write_textbuf(void* buffer,size_t size,size_t nmemb,void* param);
static size_t curl_write_data(void* ptr,size_t size,size_t nmemb,void* stream);
int dpmUpdateDPs();
bool dpGetDB(dp& rdp);
void dbRawRead(std::vector<char>& buf,uint16_t l,uint32_t& p,std::vector<char>& vStr);
void dbRawReadW(std::vector<char>& buf,uint16_t l,uint32_t& p,std::vector<wchar_t>& vStr);
void dbGetUINT(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr,std::uint8_t& i);
void dbGetUINT(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr,std::uint16_t& i);
void dbGetUINT(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr,std::uint32_t& i);
void dbGetStr(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr);
void dbGetWStr(std::vector<char>& buf,uint32_t& p,std::vector<char>& vStr,std::wstring& wStr);
std::wstring standardizeDate(const std::wstring& date);
bool compareDates(const std::wstring& date1,const std::wstring& date2);
bool dpGenDB(dp& oDP);
void trim(std::wstring& s);
bool vecInfSectHasVal(std::vector<vecInfSect>& vec,const std::wstring sMatch,const std::wregex vMatch);
bool vecInfHasSect(std::vector<vecInfSect>& vec,const std::wstring sMatch);
bool lineFilter(const std::wstring& line);
void drvReset(dpdb::driver& drv);
bool saveDB(dpdb& db);
void wFDB(std::ofstream& of,std::wstring& wStr);
void wFDB(std::ofstream& of,uint8_t& i);
void wFDB(std::ofstream& of,uint16_t& i);
void wFDB(std::ofstream& of,size_t i);
