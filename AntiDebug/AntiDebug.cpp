#include "AntiDebug.h"

#include <excpt.h>
#include <intrin.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <tlhelp32.h>

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

namespace
{
    // NtQueryInformationProcess 通过 GetProcAddress 动态解析，不链接 ntdll.lib。
    typedef LONG NtStatus;

    typedef NtStatus(NTAPI* NtQueryInformationProcessFn)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength);

    typedef NtStatus(NTAPI* NtCloseFn)(HANDLE Handle);

    typedef NtStatus(NTAPI* NtDuplicateObjectFn)(
        HANDLE SourceProcessHandle,
        HANDLE SourceHandle,
        HANDLE TargetProcessHandle,
        PHANDLE TargetHandle,
        ACCESS_MASK DesiredAccess,
        ULONG HandleAttributes,
        ULONG Options);

    typedef NtStatus(NTAPI* NtQueryObjectFn)(
        HANDLE Handle,
        ULONG ObjectInformationClass,
        PVOID ObjectInformation,
        ULONG ObjectInformationLength,
        PULONG ReturnLength);

    typedef NtStatus(NTAPI* NtQuerySystemInformationFn)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength);

    const ULONG ProcessBasicInformation = 0;
    const ULONG ProcessDebugPort = 7;
    const ULONG ProcessDebugObjectHandle = 0x1E;
    const ULONG ProcessDebugFlags = 0x1F;

    const ULONG ObjectTypeInformation = 2;
    const ULONG SystemKernelDebuggerInformation = 0x23;

    const wchar_t kDebugObjectTypeName[] = L"DebugObject";

    // 与 winternl.h 中 PROCESS_BASIC_INFORMATION 布局一致，自行定义以避免引入额外头文件。
    typedef struct _PROCESS_BASIC_INFORMATION_LOCAL
    {
        NtStatus ExitStatus;
        PVOID PebBaseAddress;
        ULONG_PTR AffinityMask;
        ULONG_PTR BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION_LOCAL;

    // 与 winternl.h 中 UNICODE_STRING 布局一致。
    typedef struct _UNICODE_STRING_LOCAL
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    } UNICODE_STRING_LOCAL;

    // 与 winternl.h 中 PUBLIC_OBJECT_TYPE_INFORMATION 布局一致。
    typedef struct _PUBLIC_OBJECT_TYPE_INFORMATION_LOCAL
    {
        UNICODE_STRING_LOCAL TypeName;
        ULONG Reserved[22];
    } PUBLIC_OBJECT_TYPE_INFORMATION_LOCAL;

    // 与 winternl.h 中 SYSTEM_KERNEL_DEBUGGER_INFORMATION 布局一致。
    typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_LOCAL
    {
        BOOLEAN KdDebuggerEnabled;
        BOOLEAN KdDebuggerNotPresent;
    } SYSTEM_KERNEL_DEBUGGER_INFORMATION_LOCAL;

    template <typename T>
    T GetNtdllFunction(const char* name)
    {
        return reinterpret_cast<T>(
            ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), name));
    }

    NtQueryInformationProcessFn GetNtQueryInformationProcess()
    {
        static NtQueryInformationProcessFn pfn = GetNtdllFunction<NtQueryInformationProcessFn>("NtQueryInformationProcess");
        return pfn;
    }

    NtCloseFn GetNtClose()
    {
        static NtCloseFn pfn = GetNtdllFunction<NtCloseFn>("NtClose");
        return pfn;
    }

    NtDuplicateObjectFn GetNtDuplicateObject()
    {
        static NtDuplicateObjectFn pfn = GetNtdllFunction<NtDuplicateObjectFn>("NtDuplicateObject");
        return pfn;
    }

    NtQueryObjectFn GetNtQueryObject()
    {
        static NtQueryObjectFn pfn = GetNtdllFunction<NtQueryObjectFn>("NtQueryObject");
        return pfn;
    }

    NtQuerySystemInformationFn GetNtQuerySystemInformation()
    {
        static NtQuerySystemInformationFn pfn = GetNtdllFunction<NtQuerySystemInformationFn>("NtQuerySystemInformation");
        return pfn;
    }

    ULONG_PTR GetPebAddress()
    {
#if defined(_WIN64)
        return __readgsqword(0x60);
#else
        return __readfsdword(0x30);
#endif
    }

    bool QueryInfo(HANDLE process, ULONG infoClass, PVOID buffer, ULONG bufferSize, DWORD* lastError)
    {
        if (lastError != nullptr)
        {
            *lastError = 0;
        }

        NtQueryInformationProcessFn pfn = GetNtQueryInformationProcess();
        if (pfn == nullptr)
        {
            if (lastError != nullptr)
            {
                *lastError = ERROR_PROC_NOT_FOUND;
            }
            return false;
        }

        ULONG returnLength = 0;
        NtStatus status = pfn(process, infoClass, buffer, bufferSize, &returnLength);
        if (status != 0)
        {
            // ntdll 调用不设置 GetLastError；此处把 NTSTATUS 原样写入 lastError，
            // UI 以 0x%08lX 显示，便于排查。
            if (lastError != nullptr)
            {
                *lastError = static_cast<DWORD>(status);
            }
            return false;
        }

        return true;
    }

    bool IsWhitelistedParent(const wchar_t* imagePath)
    {
        // 白名单可在此配置；默认仅放行 explorer.exe。
        static const wchar_t* const whitelist[] =
        {
            L"explorer.exe"
        };

        const wchar_t* fileName = ::wcsrchr(imagePath, L'\\');
        if (fileName != nullptr)
        {
            ++fileName;
        }
        else
        {
            fileName = imagePath;
        }

        for (const wchar_t* item : whitelist)
        {
            if (::_wcsicmp(fileName, item) == 0)
            {
                return true;
            }
        }
        return false;
    }

    bool ContainsIgnoreCase(const wchar_t* haystack, const wchar_t* needle)
    {
        if (haystack == nullptr || needle == nullptr)
        {
            return false;
        }

        size_t hayLength = ::wcslen(haystack);
        size_t needleLength = ::wcslen(needle);
        if (needleLength == 0 || hayLength < needleLength)
        {
            return false;
        }

        for (size_t i = 0; i + needleLength <= hayLength; ++i)
        {
            if (::_wcsnicmp(haystack + i, needle, needleLength) == 0)
            {
                return true;
            }
        }
        return false;
    }

    bool StartsWithIgnoreCase(const wchar_t* str, const wchar_t* prefix)
    {
        if (str == nullptr || prefix == nullptr)
        {
            return false;
        }

        size_t prefixLength = ::wcslen(prefix);
        if (prefixLength == 0 || ::wcslen(str) < prefixLength)
        {
            return false;
        }

        return ::_wcsnicmp(str, prefix, prefixLength) == 0;
    }

    bool IsObjectTypeDebugObject(HANDLE handle, DWORD* lastError)
    {
        NtQueryObjectFn query = GetNtQueryObject();
        if (query == nullptr)
        {
            if (lastError != nullptr)
            {
                *lastError = ERROR_PROC_NOT_FOUND;
            }
            return false;
        }

        ULONG needed = 0;
        NtStatus status = query(handle, ObjectTypeInformation, nullptr, 0, &needed);
        if (status != 0 && status != static_cast<NtStatus>(0xC0000004L)) // STATUS_INFO_LENGTH_MISMATCH
        {
            if (lastError != nullptr)
            {
                *lastError = static_cast<DWORD>(status);
            }
            return false;
        }

        if (needed < sizeof(PUBLIC_OBJECT_TYPE_INFORMATION_LOCAL) + sizeof(wchar_t) * 64)
        {
            needed = sizeof(PUBLIC_OBJECT_TYPE_INFORMATION_LOCAL) + sizeof(wchar_t) * 64;
        }

        BYTE* buffer = static_cast<BYTE*>(::malloc(needed));
        if (buffer == nullptr)
        {
            if (lastError != nullptr)
            {
                *lastError = ERROR_NOT_ENOUGH_MEMORY;
            }
            return false;
        }

        status = query(handle, ObjectTypeInformation, buffer, needed, &needed);
        if (status != 0)
        {
            ::free(buffer);
            if (lastError != nullptr)
            {
                *lastError = static_cast<DWORD>(status);
            }
            return false;
        }

        bool match = false;
        auto* info = reinterpret_cast<PUBLIC_OBJECT_TYPE_INFORMATION_LOCAL*>(buffer);
        if (info->TypeName.Buffer != nullptr &&
            info->TypeName.Length == static_cast<USHORT>(::wcslen(kDebugObjectTypeName) * sizeof(wchar_t)) &&
            ::_wcsnicmp(info->TypeName.Buffer, kDebugObjectTypeName, ::wcslen(kDebugObjectTypeName)) == 0)
        {
            match = true;
        }

        ::free(buffer);
        if (lastError != nullptr)
        {
            *lastError = 0;
        }
        return match;
    }

    DWORD Crc32(const void* data, size_t size)
    {
        static DWORD table[256] = {};
        static BOOL tableReady = FALSE;

        if (!tableReady)
        {
            for (DWORD i = 0; i < 256; ++i)
            {
                DWORD crc = i;
                for (int j = 0; j < 8; ++j)
                {
                    if (crc & 1)
                    {
                        crc = (crc >> 1) ^ 0xEDB88320UL;
                    }
                    else
                    {
                        crc >>= 1;
                    }
                }
                table[i] = crc;
            }
            tableReady = TRUE;
        }

        DWORD crc = 0xFFFFFFFFUL;
        const BYTE* p = static_cast<const BYTE*>(data);
        for (size_t i = 0; i < size; ++i)
        {
            crc = (crc >> 8) ^ table[(crc ^ p[i]) & 0xFF];
        }
        return crc ^ 0xFFFFFFFFUL;
    }

    DWORD ComputeImageTextCrc(DWORD* lastError)
    {
        if (lastError != nullptr)
        {
            *lastError = 0;
        }

        BYTE* base = reinterpret_cast<BYTE*>(::GetModuleHandleW(nullptr));
        if (base == nullptr)
        {
            if (lastError != nullptr)
            {
                *lastError = ERROR_DLL_NOT_FOUND;
            }
            return 0;
        }

        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            if (lastError != nullptr)
            {
                *lastError = ERROR_INVALID_IMAGE_HASH;
            }
            return 0;
        }

        IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            if (lastError != nullptr)
            {
                *lastError = ERROR_INVALID_IMAGE_HASH;
            }
            return 0;
        }

        IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            if (::memcmp(sections[i].Name, ".text", 6) == 0)
            {
                DWORD size = sections[i].Misc.VirtualSize;
                if (size == 0)
                {
                    size = sections[i].SizeOfRawData;
                }
                if (size == 0)
                {
                    if (lastError != nullptr)
                    {
                        *lastError = ERROR_INVALID_DATA;
                    }
                    return 0;
                }

                const BYTE* data = base + sections[i].VirtualAddress;
                return Crc32(data, size);
            }
        }

        if (lastError != nullptr)
        {
            *lastError = ERROR_FILE_NOT_FOUND;
        }
        return 0;
    }

    volatile DWORD g_codeCrcBaseline = 0;
    wchar_t g_benignPath[MAX_PATH * 2] = L"C:\\";
    volatile ULONGLONG g_tickCountDeltaThresholdMs = 150;

    volatile BOOL g_vehDrDetected = FALSE;

    LONG CALLBACK DrVectoredHandler(EXCEPTION_POINTERS* ExceptionInfo)
    {
        if (ExceptionInfo != nullptr &&
            ExceptionInfo->ExceptionRecord != nullptr &&
            ExceptionInfo->ExceptionRecord->ExceptionCode == 0x20474343UL)
        {
            PCONTEXT ctx = ExceptionInfo->ContextRecord;
            if (ctx != nullptr &&
                (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0 || ctx->Dr7 != 0))
            {
                g_vehDrDetected = TRUE;
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    struct WindowSearchContext
    {
        const wchar_t* const* keywords;
        int keywordCount;
        BOOL found;
    };

    BOOL CALLBACK DebuggerWindowEnumProc(HWND hwnd, LPARAM lParam)
    {
        auto* ctx = reinterpret_cast<WindowSearchContext*>(lParam);
        if (ctx == nullptr)
        {
            return TRUE;
        }

        wchar_t title[256] = {};
        int length = ::GetWindowTextW(hwnd, title, _countof(title));
        if (length > 0)
        {
            for (int i = 0; i < ctx->keywordCount; ++i)
            {
                if (ContainsIgnoreCase(title, ctx->keywords[i]))
                {
                    ctx->found = TRUE;
                    return TRUE; // 不提前停止，避免与 EnumWindows 失败混淆
                }
            }
        }
        return TRUE;
    }

    typedef bool (*ProcessNameMatcher)(const wchar_t* processName);

    bool MatchAnyProcess(ProcessNameMatcher matcher, DWORD* lastError)
    {
        if (lastError != nullptr)
        {
            *lastError = 0;
        }

        HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            DWORD err = ::GetLastError();
            if (lastError != nullptr)
            {
                *lastError = (err != 0) ? err : ERROR_GEN_FAILURE;
            }
            return false;
        }

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);

        bool found = false;
        if (::Process32FirstW(snapshot, &entry))
        {
            do
            {
                if (matcher(entry.szExeFile))
                {
                    found = true;
                    break;
                }
            } while (::Process32NextW(snapshot, &entry));
        }

        DWORD err = ::GetLastError();
        ::CloseHandle(snapshot);

        if (!found && err != 0 && err != ERROR_NO_MORE_FILES)
        {
            if (lastError != nullptr)
            {
                *lastError = err;
            }
        }
        return found;
    }

    bool MatchCheatEngine(const wchar_t* processName)
    {
        return ::_wcsnicmp(processName, L"cheatengine", 11) == 0;
    }

    bool MatchX64dbg(const wchar_t* processName)
    {
        return ::_wcsicmp(processName, L"x32dbg.exe") == 0 ||
               ::_wcsicmp(processName, L"x64dbg.exe") == 0;
    }

    bool MatchHuorongSword(const wchar_t* processName)
    {
        return ::_wcsnicmp(processName, L"hr", 2) == 0 ||
               ::_wcsnicmp(processName, L"huorong", 7) == 0;
    }

    bool MatchPCHunter(const wchar_t* processName)
    {
        return ::_wcsnicmp(processName, L"pchunter", 8) == 0;
    }
}

DetectionStatus DetectBeingDebugged(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    ULONG_PTR peb = GetPebAddress();
    if (peb == 0)
    {
        if (lastError != nullptr)
        {
            *lastError = ERROR_INVALID_ADDRESS;
        }
        return AD_FAILED;
    }

    // volatile 读取，防止 /O2 下被优化掉。
    volatile BYTE* p = reinterpret_cast<volatile BYTE*>(peb);
    BYTE beingDebugged = p[2];
    return beingDebugged != 0 ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectNtGlobalFlag(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    ULONG_PTR peb = GetPebAddress();
    if (peb == 0)
    {
        if (lastError != nullptr)
        {
            *lastError = ERROR_INVALID_ADDRESS;
        }
        return AD_FAILED;
    }

#if defined(_WIN64)
    const ptrdiff_t ntGlobalFlagOffset = 0xBC;
#else
    const ptrdiff_t ntGlobalFlagOffset = 0x68;
#endif

    volatile DWORD* ntGlobalFlag = reinterpret_cast<volatile DWORD*>(peb + ntGlobalFlagOffset);
    return ((*ntGlobalFlag) & 0x70) != 0 ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectIsDebuggerPresent(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    return ::IsDebuggerPresent() ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectCheckRemoteDebuggerPresent(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    BOOL present = FALSE;
    BOOL ok = ::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &present);
    if (!ok)
    {
        DWORD err = ::GetLastError();
        if (lastError != nullptr)
        {
            *lastError = (err != 0) ? err : ERROR_GEN_FAILURE;
        }
        return AD_FAILED;
    }

    return present ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectDebugPort(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    DWORD debugPort = 0;
    if (!QueryInfo(::GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), lastError))
    {
        return AD_FAILED;
    }

    return debugPort != 0 ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectDebugObjectHandle(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    HANDLE debugObject = nullptr;
    if (!QueryInfo(::GetCurrentProcess(), ProcessDebugObjectHandle, &debugObject, sizeof(debugObject), lastError))
    {
        return AD_FAILED;
    }

    return debugObject != nullptr ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectDebugFlags(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    ULONG debugFlags = 1;
    if (!QueryInfo(::GetCurrentProcess(), ProcessDebugFlags, &debugFlags, sizeof(debugFlags), lastError))
    {
        return AD_FAILED;
    }

    // 被调试时该值返回 0；正常进程返回 1。
    return debugFlags == 0 ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectParentProcess(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    PROCESS_BASIC_INFORMATION_LOCAL pbi = {};
    if (!QueryInfo(::GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), lastError))
    {
        return AD_FAILED;
    }

    if (pbi.InheritedFromUniqueProcessId == 0)
    {
        // 无有效父进程 PID 时视为未检测到。
        return AD_NOT_DETECTED;
    }

    HANDLE parent = ::OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        static_cast<DWORD>(pbi.InheritedFromUniqueProcessId));
    if (parent == nullptr)
    {
        DWORD err = ::GetLastError();
        if (lastError != nullptr)
        {
            *lastError = (err != 0) ? err : ERROR_ACCESS_DENIED;
        }
        return AD_FAILED;
    }

    wchar_t imagePath[MAX_PATH * 2] = {};
    DWORD size = static_cast<DWORD>(_countof(imagePath));
    BOOL ok = ::QueryFullProcessImageNameW(parent, 0, imagePath, &size);
    DWORD err = ::GetLastError();
    ::CloseHandle(parent);

    if (!ok)
    {
        if (lastError != nullptr)
        {
            *lastError = (err != 0) ? err : ERROR_GEN_FAILURE;
        }
        return AD_FAILED;
    }

    return IsWhitelistedParent(imagePath) ? AD_NOT_DETECTED : AD_DETECTED;
}

DetectionStatus DetectNtCloseInvalidHandle(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    NtCloseFn close = GetNtClose();
    if (close == nullptr)
    {
        if (lastError != nullptr)
        {
            *lastError = ERROR_PROC_NOT_FOUND;
        }
        return AD_FAILED;
    }

    // volatile 防止编译器把无效句柄调用优化掉。
    volatile HANDLE invalidHandle = reinterpret_cast<HANDLE>(static_cast<INT_PTR>(0x9999));
    BOOL caught = FALSE;

    __try
    {
        close(invalidHandle);
    }
    __except (GetExceptionCode() == 0xC0000008L ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        caught = TRUE;
    }

    // 本地 SEH 捕获到 STATUS_INVALID_HANDLE，说明没有调试器截获该异常。
    return caught ? AD_NOT_DETECTED : AD_DETECTED;
}

DetectionStatus DetectDebugObject(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    NtDuplicateObjectFn duplicate = GetNtDuplicateObject();
    if (duplicate == nullptr)
    {
        if (lastError != nullptr)
        {
            *lastError = ERROR_PROC_NOT_FOUND;
        }
        return AD_FAILED;
    }

    // 按规格先尝试复制 (HANDLE)-1 伪句柄；正常进程得到的是 Process 类型。
    HANDLE pseudoDup = nullptr;
    NtStatus status = duplicate(
        ::GetCurrentProcess(),
        reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-1)),
        ::GetCurrentProcess(),
        &pseudoDup,
        0,
        0,
        DUPLICATE_SAME_ACCESS);

    if (status == 0 && pseudoDup != nullptr)
    {
        bool debugObject = IsObjectTypeDebugObject(pseudoDup, lastError);
        ::CloseHandle(pseudoDup);
        if (lastError != nullptr && *lastError != 0)
        {
            return AD_FAILED;
        }
        if (debugObject)
        {
            return AD_DETECTED;
        }
    }

    // 复制伪句柄得到的是 Process 类型，无法命中 DebugObject；
    // 因此改用 ProcessDebugObjectHandle 获取真实调试对象句柄后再确认类型。
    HANDLE debugObjectHandle = nullptr;
    if (!QueryInfo(::GetCurrentProcess(), ProcessDebugObjectHandle, &debugObjectHandle, sizeof(debugObjectHandle), lastError))
    {
        return AD_FAILED;
    }
    if (debugObjectHandle == nullptr)
    {
        return AD_NOT_DETECTED;
    }

    HANDLE duplicated = nullptr;
    status = duplicate(
        ::GetCurrentProcess(),
        debugObjectHandle,
        ::GetCurrentProcess(),
        &duplicated,
        0,
        0,
        DUPLICATE_SAME_ACCESS);
    if (status != 0 || duplicated == nullptr)
    {
        if (lastError != nullptr)
        {
            *lastError = static_cast<DWORD>(status);
        }
        return AD_FAILED;
    }

    bool debugObject = IsObjectTypeDebugObject(duplicated, lastError);
    ::CloseHandle(duplicated);
    if (lastError != nullptr && *lastError != 0)
    {
        return AD_FAILED;
    }

    return debugObject ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectWindowDebugger(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    // 黑名单数组可在此配置。
    static const wchar_t* const keywords[] =
    {
        L"x32dbg",
        L"x64dbg",
        L"ida",
        L"ollydbg",
        L"windbg",
        L"Cheat Engine"
    };

    WindowSearchContext ctx = {};
    ctx.keywords = keywords;
    ctx.keywordCount = static_cast<int>(_countof(keywords));
    ctx.found = FALSE;

    BOOL ok = ::EnumWindows(DebuggerWindowEnumProc, reinterpret_cast<LPARAM>(&ctx));
    if (!ok && !ctx.found)
    {
        DWORD err = ::GetLastError();
        if (lastError != nullptr)
        {
            *lastError = (err != 0) ? err : ERROR_GEN_FAILURE;
        }
        return AD_FAILED;
    }

    return ctx.found ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectTickCountDelta(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    volatile ULONGLONG before = ::GetTickCount64();
    ::Sleep(100);
    volatile ULONGLONG after = ::GetTickCount64();
    ULONGLONG delta = after - before;

    // 注意：多线程/高负载下可能出现误报，阈值可按环境调整。
    return (delta > g_tickCountDeltaThresholdMs) ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectCodeCRC32(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    DWORD baseline = g_codeCrcBaseline;
    if (baseline == 0)
    {
        if (lastError != nullptr)
        {
            *lastError = ERROR_INVALID_DATA; // 未注入基准值
        }
        return AD_FAILED;
    }

    DWORD current = ComputeImageTextCrc(lastError);
    if (lastError != nullptr && *lastError != 0)
    {
        return AD_FAILED;
    }

    return (current == baseline) ? AD_NOT_DETECTED : AD_DETECTED;
}

DetectionStatus DetectDrxContext(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!::GetThreadContext(::GetCurrentThread(), &ctx))
    {
        DWORD err = ::GetLastError();
        if (lastError != nullptr)
        {
            *lastError = (err != 0) ? err : ERROR_GEN_FAILURE;
        }
        return AD_FAILED;
    }

    bool hardwareBreakpoint =
        ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 || ctx.Dr7 != 0;
    return hardwareBreakpoint ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectDrxVEH(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    PVOID handler = ::AddVectoredExceptionHandler(1, DrVectoredHandler);
    if (handler == nullptr)
    {
        DWORD err = ::GetLastError();
        if (lastError != nullptr)
        {
            *lastError = (err != 0) ? err : ERROR_GEN_FAILURE;
        }
        return AD_FAILED;
    }

    g_vehDrDetected = FALSE;
    ::RaiseException(0x20474343UL, 0, 0, nullptr);
    ::RemoveVectoredExceptionHandler(handler);

    return g_vehDrDetected ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectScyllaHide(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    static const wchar_t* const modules[] =
    {
        L"ScyllaHideX64.dll",
        L"ScyllaHideX86.dll",
        L"ScyllaHide.dll",
        L"HookLibraryx64.dll",
        L"HookLibraryx86.dll",
        L"HookLibrary.dll"
    };

    for (const wchar_t* name : modules)
    {
        if (::GetModuleHandleW(name) != nullptr)
        {
            return AD_DETECTED;
        }
    }

    return AD_NOT_DETECTED;
}

DetectionStatus DetectBenignPath(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    wchar_t modulePath[MAX_PATH * 2] = {};
    DWORD length = ::GetModuleFileNameW(nullptr, modulePath, static_cast<DWORD>(_countof(modulePath)));
    if (length == 0)
    {
        DWORD err = ::GetLastError();
        if (lastError != nullptr)
        {
            *lastError = (err != 0) ? err : ERROR_GEN_FAILURE;
        }
        return AD_FAILED;
    }
    if (length >= _countof(modulePath))
    {
        if (lastError != nullptr)
        {
            *lastError = ERROR_INSUFFICIENT_BUFFER;
        }
        return AD_FAILED;
    }

    return StartsWithIgnoreCase(modulePath, g_benignPath) ? AD_NOT_DETECTED : AD_DETECTED;
}

DetectionStatus DetectKernelDebugger(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    NtQuerySystemInformationFn query = GetNtQuerySystemInformation();
    if (query == nullptr)
    {
        if (lastError != nullptr)
        {
            *lastError = ERROR_PROC_NOT_FOUND;
        }
        return AD_FAILED;
    }

    SYSTEM_KERNEL_DEBUGGER_INFORMATION_LOCAL info = {};
    ULONG returnLength = 0;
    NtStatus status = query(SystemKernelDebuggerInformation, &info, sizeof(info), &returnLength);
    if (status != 0)
    {
        if (lastError != nullptr)
        {
            *lastError = static_cast<DWORD>(status);
        }
        return AD_FAILED;
    }

    return info.KdDebuggerEnabled ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectCheatEngine(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    bool found = MatchAnyProcess(MatchCheatEngine, lastError);
    if (lastError != nullptr && *lastError != 0)
    {
        return AD_FAILED;
    }
    return found ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectX64dbg(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    bool found = MatchAnyProcess(MatchX64dbg, lastError);
    if (lastError != nullptr && *lastError != 0)
    {
        return AD_FAILED;
    }
    return found ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectHuorongSword(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    bool found = MatchAnyProcess(MatchHuorongSword, lastError);
    if (lastError != nullptr && *lastError != 0)
    {
        return AD_FAILED;
    }
    return found ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectPCHunter(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    bool found = MatchAnyProcess(MatchPCHunter, lastError);
    if (lastError != nullptr && *lastError != 0)
    {
        return AD_FAILED;
    }
    return found ? AD_DETECTED : AD_NOT_DETECTED;
}

void InitCrcBaseline(DWORD crc)
{
    g_codeCrcBaseline = crc;
}

DWORD ComputeCodeCrc32(DWORD* lastError)
{
    return ComputeImageTextCrc(lastError);
}

void InitBenignPath(const wchar_t* path)
{
    if (path == nullptr || *path == L'\0')
    {
        path = L"C:\\";
    }

    size_t length = ::wcslen(path);
    if (length >= _countof(g_benignPath))
    {
        length = _countof(g_benignPath) - 1;
    }

    ::memcpy(g_benignPath, path, length * sizeof(wchar_t));
    g_benignPath[length] = L'\0';
}

namespace
{
    const DetectionItem g_detectionItems[] =
    {
        { 1, L"PEB.BeingDebugged", L"读取 PEB.BeingDebugged（x64: gs:[0x60]+2；x86: fs:[0x30]+2）", &DetectBeingDebugged },
        { 2, L"PEB.NtGlobalFlag", L"读取 PEB.NtGlobalFlag 低字节，若 & 0x70 非 0 表示被调试", &DetectNtGlobalFlag },
        { 3, L"IsDebuggerPresent", L"调用 kernel32!IsDebuggerPresent", &DetectIsDebuggerPresent },
        { 4, L"CheckRemoteDebuggerPresent", L"调用 kernel32!CheckRemoteDebuggerPresent(GetCurrentProcess())", &DetectCheckRemoteDebuggerPresent },
        { 5, L"DebugPort", L"NtQueryInformationProcess(ProcessDebugPort=7)，端口非 0 即被调试", &DetectDebugPort },
        { 6, L"DebugObjectHandle", L"NtQueryInformationProcess(ProcessDebugObjectHandle=0x1E)，句柄非空即被调试", &DetectDebugObjectHandle },
        { 7, L"DebugFlags", L"NtQueryInformationProcess(ProcessDebugFlags=0x1F)，被调试时返回 0", &DetectDebugFlags },
        { 8, L"父进程检测", L"查询父进程名，不在白名单(explorer.exe)即被调试", &DetectParentProcess },
        { 9, L"NtClose 无效句柄", L"动态解析 ntdll!NtClose 对 (HANDLE)0x9999 调用，SEH 捕获 STATUS_INVALID_HANDLE", &DetectNtCloseInvalidHandle },
        { 10, L"DebugObject 类型", L"NtDuplicateObject 复制调试对象句柄，NtQueryObject 判断类型名为 DebugObject", &DetectDebugObject },
        { 11, L"窗口名黑名单", L"EnumWindows+GetWindowTextW，匹配调试器窗口名关键字", &DetectWindowDebugger },
        { 12, L"TickCount 差值", L"GetTickCount64 前后 Sleep(100)，差值超阈值判定被调试", &DetectTickCountDelta },
        { 13, L".text CRC32", L"解析 PE .text 段计算 CRC32，与 InitCrcBaseline 注入的基准比对", &DetectCodeCRC32 },
        { 14, L"硬件断点上下文", L"GetThreadContext 读 DR0-DR7（CONTEXT_DEBUG_REGISTERS）", &DetectDrxContext },
        { 15, L"硬件断点 VEH", L"AddVectoredExceptionHandler+RaiseException，回调读 ContextRecord 的 DR", &DetectDrxVEH },
        { 16, L"ScyllaHide 特征", L"检测 ScyllaHide 相关模块是否加载", &DetectScyllaHide },
        { 17, L"路径白名单", L"GetModuleFileNameW 与期望路径比对（默认 C:\\）", &DetectBenignPath },
        { 18, L"内核调试器", L"NtQuerySystemInformation(SystemKernelDebuggerInformation=0x23)", &DetectKernelDebugger },
        { 19, L"Cheat Engine 进程", L"Toolhelp32Snapshot 枚举进程名，匹配 cheatengine*", &DetectCheatEngine },
        { 20, L"x64dbg/x32dbg 进程", L"Toolhelp32Snapshot 枚举进程名，匹配 x32dbg.exe/x64dbg.exe", &DetectX64dbg },
        { 21, L"火绒剑进程", L"Toolhelp32Snapshot 枚举进程名，匹配 HR*/Huorong*", &DetectHuorongSword },
        { 22, L"PCHunter 进程", L"Toolhelp32Snapshot 枚举进程名，匹配 PCHunter*", &DetectPCHunter },
    };
}

int GetDetectionCount()
{
    return static_cast<int>(sizeof(g_detectionItems) / sizeof(g_detectionItems[0]));
}

const DetectionItem* GetDetectionItems()
{
    return g_detectionItems;
}
