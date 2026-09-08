#include "AntiDebug.h"

#include <excpt.h>
#include <intrin.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <array>
#include <tlhelp32.h>
#include <shlwapi.h>

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

    const NtStatus kNtStatusInfoLengthMismatch = static_cast<NtStatus>(0xC0000004L);
    const NtStatus kNtStatusInvalidHandle = static_cast<NtStatus>(0xC0000008L);
    const NtStatus kNtStatusPortNotSet = static_cast<NtStatus>(0xC0000353L);

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
        HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            return nullptr;
        }
        return reinterpret_cast<T>(::GetProcAddress(ntdll, name));
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

    // 保护式读取任意进程内存：先 VirtualQuery 确认页面已提交、可读且不跨 region，
    // 避免被 hook/反反调试工具改写页保护时直接访问违例。
    bool SafeReadBytes(const void* addr, void* buf, SIZE_T size)
    {
        if (addr == nullptr || buf == nullptr || size == 0)
        {
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi = {};
        if (::VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
        {
            return false;
        }
        if (mbi.State != MEM_COMMIT)
        {
            return false;
        }
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
        {
            return false;
        }

        const BYTE* start = static_cast<const BYTE*>(addr);
        const BYTE* regionEnd = static_cast<const BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (start + size > regionEnd)
        {
            return false;
        }

        ::memcpy(buf, addr, size);
        return true;
    }

    BYTE* GetCurrentPeb()
    {
#if defined(_WIN64)
        return reinterpret_cast<BYTE*>(__readgsqword(0x60));
#else
        return reinterpret_cast<BYTE*>(__readfsdword(0x30));
#endif
    }

    // 保护式读取 PEB 字段（偏移基于 x64: gs:[0x60]；x86: fs:[0x30]）。
    bool TryReadPeb(DWORD offset, void* out, SIZE_T size)
    {
        BYTE* peb = GetCurrentPeb();
        if (peb == nullptr)
        {
            return false;
        }
        return SafeReadBytes(peb + offset, out, size);
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

    bool QueryInfoAllowStatus(HANDLE process, ULONG infoClass, PVOID buffer, ULONG bufferSize, NtStatus allowedStatus, DWORD* lastError)
    {
        DWORD statusCode = 0;
        if (QueryInfo(process, infoClass, buffer, bufferSize, &statusCode))
        {
            if (lastError != nullptr)
            {
                *lastError = 0;
            }
            return true;
        }
        if (static_cast<NtStatus>(statusCode) == allowedStatus)
        {
            if (lastError != nullptr)
            {
                *lastError = 0;
            }
            return true;
        }
        if (lastError != nullptr)
        {
            *lastError = statusCode;
        }
        return false;
    }

    void CloseDebugObjectHandle(HANDLE handle)
    {
        if (handle == nullptr)
        {
            return;
        }

        NtCloseFn close = GetNtClose();
        if (close != nullptr)
        {
            close(handle);
            return;
        }
        ::CloseHandle(handle);
    }

    bool IsWhitelistedParent(const wchar_t* imagePath)
    {
        // 白名单可在此配置。
        static const wchar_t* const whitelist[] =
        {
            L"explorer.exe",
            L"cmd.exe",
            L"powershell.exe",
            L"pwsh.exe",
            L"windowsterminal.exe",
            L"openconsole.exe",
            L"svchost.exe",
            L"userinit.exe",
            L"winlogon.exe",
            L"services.exe"
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
        if (status != 0 && status != kNtStatusInfoLengthMismatch)
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
        // 函数级 static 局部对象在 C++11 起保证线程安全的初始化，
        // 避免原实现中无锁的 tableReady 标志产生竞态。
        static const std::array<DWORD, 256> s_table = []() {
            std::array<DWORD, 256> table = {};
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
            return table;
        }();

        DWORD crc = 0xFFFFFFFFUL;
        const BYTE* p = static_cast<const BYTE*>(data);
        for (size_t i = 0; i < size; ++i)
        {
            crc = (crc >> 8) ^ s_table[(crc ^ p[i]) & 0xFF];
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
                if (sections[i].SizeOfRawData != 0 && size > sections[i].SizeOfRawData)
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
                MEMORY_BASIC_INFORMATION mbi = {};
                SIZE_T readable = 0;
                const BYTE* cursor = data;
                SIZE_T remaining = size;
                while (remaining > 0)
                {
                    if (::VirtualQuery(cursor, &mbi, sizeof(mbi)) == 0)
                    {
                        break;
                    }
                    if (mbi.State != MEM_COMMIT)
                    {
                        break;
                    }
                    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
                    {
                        break;
                    }

                    const BYTE* regionEnd = static_cast<const BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
                    SIZE_T chunk = static_cast<SIZE_T>(regionEnd - cursor);
                    if (chunk > remaining)
                    {
                        chunk = remaining;
                    }
                    readable += chunk;
                    cursor += chunk;
                    remaining -= chunk;
                }

                if (readable == 0 || remaining != 0)
                {
                    // readable==0 表示整段不可读；remaining!=0 表示读取中遇页保护被中断。
                    // 两者都意味着 CRC 只能覆盖部分 .text，应失败而非返回部分结果，
                    // 否则与基准比较会产生永久误报。
                    if (lastError != nullptr)
                    {
                        *lastError = ERROR_INVALID_ADDRESS;
                    }
                    return 0;
                }

                return Crc32(data, readable);
            }
        }

        if (lastError != nullptr)
        {
            *lastError = ERROR_FILE_NOT_FOUND;
        }
        return 0;
    }

    // 以下全局均在"创建工作线程之前"由主线程写入（InitCrcBaseline / InitBenignPath），
    // 线程创建构成 happens-before，检测线程读取无需再加锁，故用普通类型即可。
    DWORD g_codeCrcBaseline = 0;
    BOOL g_codeCrcReady = FALSE;
    wchar_t g_benignPath[MAX_PATH * 2] = {};
    ULONGLONG g_tickCountDeltaThresholdMs = 400;

    // g_vehDrDetected 只由 VEH 回调写、DetectDrxVEH 同线程同步读（RaiseException 返回前回调已完成）。
    BOOL g_vehDrDetected = FALSE;
    static constexpr DWORD kCustomCode = 0x20474343UL;

    bool HasHardwareBreakpoint(const CONTEXT* ctx)
    {
        if (ctx == nullptr)
        {
            return false;
        }
        // DR7 低 8 位为 DR0-DR3 的 local/global enable；bit10 等保留位常为 1，不能用 Dr7 != 0。
        return (ctx->Dr7 & 0xFF) != 0;
    }

    LONG CALLBACK DrVectoredHandler(PEXCEPTION_POINTERS pExcept)
    {
        // ① 只处理自己抛的异常码，其余一律继续分发（不吞别人的异常）
        if (pExcept == nullptr ||
            pExcept->ExceptionRecord == nullptr ||
            pExcept->ContextRecord == nullptr ||
            pExcept->ExceptionRecord->ExceptionCode != kCustomCode)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        PCONTEXT ctx = pExcept->ContextRecord;

        // ③ 防御：ContextFlags 未声明含调试寄存器时，DR 字段不可信
        if ((ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS) != 0)
        {
            // ④ 判定：地址非 0 且 DR7 使能位（L0/G0..L3/G3 = 低 8 位）非 0
            if ((ctx->Dr0 | ctx->Dr1 | ctx->Dr2 | ctx->Dr3) != 0 &&
                (ctx->Dr7 & 0xFF) != 0)
            {
                g_vehDrDetected = TRUE;
            }
        }

        // ② 必须吞掉自己的异常，否则未处理异常会崩掉进程
        return EXCEPTION_CONTINUE_EXECUTION;
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
        if (ctx == nullptr) return FALSE;

        wchar_t title[256] = {};
        if (::GetWindowTextW(hwnd, title, _countof(title)) <= 0)
        {
            return TRUE;  // 无标题/被 UIPI 拦截，跳过
        }

        for (int i = 0; i < ctx->keywordCount; i++)
        {
            if (::StrStrIW(title, ctx->keywords[i]) != nullptr)
            {  // 大小写不敏感
                ctx->found = TRUE;
                return FALSE;  // 提前终止，EnumWindows 将返回 FALSE（属正常）
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
        return ::_wcsicmp(processName, L"HrSword.exe") == 0 ||
               ::_wcsicmp(processName, L"HipsMain.exe") == 0 ||
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

    // PEB.BeingDebugged 偏移 0x02（x64/x86 一致）。
    BYTE beingDebugged = 0;
    if (!TryReadPeb(2, &beingDebugged, sizeof(beingDebugged)))
    {
        if (lastError != nullptr)
        {
            *lastError = ERROR_INVALID_ADDRESS;
        }
        return AD_FAILED;
    }

    return beingDebugged != 0 ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectNtGlobalFlag(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

#if defined(_WIN64)
    const DWORD ntGlobalFlagOffset = 0xBC;
#else
    const DWORD ntGlobalFlagOffset = 0x68;
#endif

    DWORD ntGlobalFlag = 0;
    if (!TryReadPeb(ntGlobalFlagOffset, &ntGlobalFlag, sizeof(ntGlobalFlag)))
    {
        if (lastError != nullptr)
        {
            *lastError = ERROR_INVALID_ADDRESS;
        }
        return AD_FAILED;
    }

    return (ntGlobalFlag & 0x70) != 0 ? AD_DETECTED : AD_NOT_DETECTED;
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

    HANDLE debugPort = nullptr;
    if (!QueryInfo(::GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), lastError))
    {
        return AD_FAILED;
    }

    return debugPort != nullptr ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectDebugObjectHandle(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    HANDLE debugObject = nullptr;
    if (!QueryInfoAllowStatus(
            ::GetCurrentProcess(),
            ProcessDebugObjectHandle,
            &debugObject,
            sizeof(debugObject),
            kNtStatusPortNotSet,
            lastError))
    {
        return AD_FAILED;
    }

    if (debugObject == nullptr)
    {
        return AD_NOT_DETECTED;
    }

    CloseDebugObjectHandle(debugObject);
    return AD_DETECTED;
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

    // 0xDEADBEEF 远大于常规句柄分配范围，避免与进程真实句柄值撞上导致误关闭有效句柄；
    // NtClose 是外部函数调用（存在不可知副作用），编译器不会将其删除，无需 volatile。
    HANDLE invalidHandle = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0xDEADBEEF));
    BOOL caught = FALSE;

    __try
    {
        close(invalidHandle);
    }
     __except (GetExceptionCode() == static_cast<DWORD>(kNtStatusInvalidHandle) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        caught = TRUE;
    }

    // 内核 ObpCloseHandle 仅在进程存在调试端口（或启用了内核调试器）时，
    // 才会把 STATUS_INVALID_HANDLE 作为异常投递给用户态；
    // 正常进程直接返回错误码、不产生异常 → caught=FALSE。
    // 注意：若调试器把该 first-chance 异常标记为已处理并吞掉，本地 SEH 捕获不到 → 漏报。
    return caught ? AD_DETECTED : AD_NOT_DETECTED;
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
    if (!QueryInfoAllowStatus(
            ::GetCurrentProcess(),
            ProcessDebugObjectHandle,
            &debugObjectHandle,
            sizeof(debugObjectHandle),
            kNtStatusPortNotSet,
            lastError))
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
    CloseDebugObjectHandle(debugObjectHandle);
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
    if (lastError != nullptr) *lastError = 0;

    static const wchar_t* const keywords[] = {
        L"x32dbg", L"x64dbg",
        L"ida pro", L"ida free", L"ida64", L"ida32",
        L"ollydbg", L"windbg", L"cheat engine", L"dnspy"
    };

    WindowSearchContext ctx = {};
    ctx.keywords = keywords;
    ctx.keywordCount = static_cast<int>(_countof(keywords));
    ctx.found = FALSE;

    ::EnumWindows(DebuggerWindowEnumProc, reinterpret_cast<LPARAM>(&ctx));

    // 类名信号补充（OllyDbg 默认类名，对 UIPI 不敏感）
    if (!ctx.found && ::FindWindowW(L"10001100", nullptr) != nullptr)
    {
        ctx.found = TRUE;
    }

    // EnumWindows 返回 FALSE 且非提前终止才算失败；
    // 该场景 GetLastError 不可靠，仅做兜底，不写具体错误码
    return ctx.found ? AD_DETECTED : AD_NOT_DETECTED;
}

DetectionStatus DetectTickCountDelta(DWORD* lastError)
{
    if (lastError != nullptr)
    {
        *lastError = 0;
    }

    ULONGLONG before = ::GetTickCount64();
    ::Sleep(100);
    ULONGLONG after = ::GetTickCount64();
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
    if (!g_codeCrcReady)
    {
        if (lastError != nullptr)
        {
            *lastError = ERROR_INVALID_DATA;
        }
        return AD_FAILED;
    }

    DWORD currentError = 0;
    DWORD current = ComputeImageTextCrc(&currentError);
    if (currentError != 0)
    {
        if (lastError != nullptr)
        {
            *lastError = currentError;
        }
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

    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        DWORD err = ::GetLastError();
        if (lastError != nullptr)
        {
            *lastError = (err != 0) ? err : ERROR_GEN_FAILURE;
        }
        return AD_FAILED;
    }

    const DWORD currentPid = ::GetCurrentProcessId();
    const DWORD currentTid = ::GetCurrentThreadId();
    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);

    DetectionStatus result = AD_NOT_DETECTED;
    BOOL queried = FALSE;

    if (::Thread32First(snapshot, &entry))
    {
        do
        {
            if (entry.th32OwnerProcessID != currentPid || entry.th32ThreadID == currentTid)
            {
                continue;
            }

            HANDLE thread = ::OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
            if (thread == nullptr)
            {
                continue;
            }

            if (::SuspendThread(thread) == static_cast<DWORD>(-1))
            {
                ::CloseHandle(thread);
                continue;
            }

            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            BOOL ok = ::GetThreadContext(thread, &ctx);
            ::ResumeThread(thread);
            ::CloseHandle(thread);

            if (!ok)
            {
                continue;
            }

            queried = TRUE;
            if (HasHardwareBreakpoint(&ctx))
            {
                result = AD_DETECTED;
                break;
            }
        } while (::Thread32Next(snapshot, &entry));
    }

    ::CloseHandle(snapshot);

    if (result == AD_DETECTED)
    {
        return AD_DETECTED;
    }

    if (!queried)
    {
        if (lastError != nullptr)
        {
            *lastError = ERROR_NOT_FOUND;
        }
        return AD_FAILED;
    }

    return AD_NOT_DETECTED;
}

DetectionStatus DetectDrxVEH(DWORD* lastError)
{
    if (lastError != nullptr) *lastError = 0;

    g_vehDrDetected = FALSE;
    PVOID handler = ::AddVectoredExceptionHandler(1, DrVectoredHandler);
    if (handler == nullptr)
    {
        // ⑥ AddVectoredExceptionHandler 失败时 GetLastError 不可靠，仅兜底
        if (lastError != nullptr) *lastError = ERROR_GEN_FAILURE;
        return AD_FAILED;
    }

    ::RaiseException(kCustomCode, 0, 0, nullptr);  // 同步：返回前回调已执行
    ::RemoveVectoredExceptionHandler(handler);

    return g_vehDrDetected ? AD_DETECTED : AD_NOT_DETECTED;
}


static const char* const kNtdllHookTargets[] = {
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "NtQueryObject",
    "NtClose",
    "NtDuplicateObject",
    "NtQuerySystemInformation",
    "NtSetInformationProcess",
    "NtOpenFile",
    "NtCreateSection",
    "NtMapViewOfSection",
    "NtYieldExecution",
    "NtGetContextThread",
    "NtSetContextThread",
    "NtContinue",
    "NtCreateThreadEx",
    "NtQuerySystemTime",
    "NtQueryPerformanceCounter",
    "KiUserExceptionDispatcher",
};

static bool IsPrivateExec(const void* addr)
{
    if (addr == nullptr) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (::VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Type == MEM_IMAGE) return false;
    const DWORD exec = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & exec) != 0;
}

static bool IsScyllaJumper(const BYTE* p, const BYTE* va, SIZE_T n)
{
#ifdef _WIN64
    // ScyllaHide x64: nop; jmp qword ptr [rip+0]; <abs64>
    if (n >= 15 &&
        p[0] == 0x90 && p[1] == 0xFF && p[2] == 0x25 &&
        *reinterpret_cast<const DWORD*>(p + 3) == 0)
    {
        return true;
    }
    // 无 nop 的同款绝对跳，目标落在匿名可执行页
    if (n >= 14 && p[0] == 0xFF && p[1] == 0x25 &&
        *reinterpret_cast<const DWORD*>(p + 2) == 0)
    {
        void* target = *reinterpret_cast<void* const*>(p + 6);
        return IsPrivateExec(target);
    }
#else
    if (n >= 5 && p[0] == 0xE9)
    {
        const INT32 rel = *reinterpret_cast<const INT32*>(p + 1);
        void* target = reinterpret_cast<void*>(
            reinterpret_cast<ULONG_PTR>(va) + 5 + rel);
        return IsPrivateExec(target);
    }
#endif
    return false;
}

static bool DetectWow64TransitionHook()
{
#ifdef _WIN64
    return false;
#else
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) return false;
    FARPROC pExport = ::GetProcAddress(ntdll, "Wow64Transition");
    if (pExport == nullptr) return false;

    void* gate = nullptr;
    if (!SafeReadBytes(pExport, &gate, sizeof(gate)) || gate == nullptr) return false;

    BYTE farJmp[7]{};
    if (!SafeReadBytes(gate, farJmp, sizeof(farJmp))) return false;
    if (farJmp[0] != 0xEA) return false;

    const ULONG dest = *reinterpret_cast<ULONG*>(farJmp + 1);
    // 正常 wow64cpu 门目标落在 wow64cpu.dll 映像内（MEM_IMAGE，selector 0x33）；
    // ScyllaHide 把 selector 改为 0x23 且目标位于匿名可执行页（HookedNativeCallInternal）。
    // 统一按"目标是否在匿名可执行页"判定即可覆盖两种特征。
    return IsPrivateExec(reinterpret_cast<void*>(static_cast<ULONG_PTR>(dest)));
#endif
}

DetectionStatus DetectScyllaHide(DWORD* lastError)
{
    if (lastError != nullptr) *lastError = 0;

#if defined(_WIN64)
    const DWORD osBuildOffset = 0x120;
#else
    const DWORD osBuildOffset = 0x0AC;
#endif
    USHORT osBuild = 0;
    if (!TryReadPeb(osBuildOffset, &osBuild, sizeof(osBuild)))
    {
        if (lastError != nullptr) *lastError = ERROR_INVALID_ADDRESS;
        return AD_FAILED;
    }
    // ScyllaHide VersionPatch.h: FAKE_VERSION = 1337
    if (osBuild == 1337) return AD_DETECTED;

    if (DetectWow64TransitionHook()) return AD_DETECTED;

    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr)
    {
        if (lastError != nullptr) *lastError = ERROR_MOD_NOT_FOUND;
        return AD_FAILED;
    }

    BYTE mem[16]{};
    for (auto api : kNtdllHookTargets)
    {
        FARPROC fn = ::GetProcAddress(ntdll, api);
        if (fn == nullptr) continue;
        if (!SafeReadBytes(fn, mem, sizeof(mem))) continue;
        if (IsScyllaJumper(mem, reinterpret_cast<const BYTE*>(fn), sizeof(mem)))
            return AD_DETECTED;
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

    if (g_benignPath[0] == L'\0')
    {
        if (lastError != nullptr)
        {
            *lastError = ERROR_INVALID_DATA;
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

    return (info.KdDebuggerEnabled && !info.KdDebuggerNotPresent) ? AD_DETECTED : AD_NOT_DETECTED;
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
    g_codeCrcReady = TRUE;
}

DWORD ComputeCodeCrc32(DWORD* lastError)
{
    return ComputeImageTextCrc(lastError);
}

void InitBenignPath(const wchar_t* path)
{
    if (path == nullptr || *path == L'\0')
    {
        g_benignPath[0] = L'\0';
        return;
    }

    size_t length = ::wcslen(path);
    if (length >= _countof(g_benignPath))
    {
        length = _countof(g_benignPath) - 1;
    }

    ::memcpy(g_benignPath, path, length * sizeof(wchar_t));
    g_benignPath[length] = L'\0';
}

void InitDefaultBenignPath()
{
    wchar_t modulePath[MAX_PATH * 2] = {};
    DWORD length = ::GetModuleFileNameW(nullptr, modulePath, static_cast<DWORD>(_countof(modulePath)));
    if (length == 0 || length >= _countof(modulePath))
    {
        g_benignPath[0] = L'\0';
        return;
    }

    wchar_t* slash = ::wcsrchr(modulePath, L'\\');
    if (slash != nullptr)
    {
        slash[1] = L'\0';
    }

    InitBenignPath(modulePath);
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
        { 8, L"父进程检测", L"查询父进程名，不在白名单(explorer/cmd/powershell/WindowsTerminal 等)即被调试", &DetectParentProcess },
        { 9, L"NtClose 无效句柄", L"动态解析 ntdll!NtClose 对 (HANDLE)0xDEADBEEF 调用，SEH 捕获 STATUS_INVALID_HANDLE", &DetectNtCloseInvalidHandle },
        { 10, L"DebugObject 类型", L"NtDuplicateObject 复制调试对象句柄，NtQueryObject 判断类型名为 DebugObject", &DetectDebugObject },
        { 11, L"窗口名黑名单", L"EnumWindows+GetWindowTextW，匹配调试器窗口名关键字（避免短词误报）", &DetectWindowDebugger },
        { 12, L"TickCount 差值", L"GetTickCount64 前后 Sleep(100)，差值超阈值判定被调试", &DetectTickCountDelta },
        { 13, L".text CRC32", L"解析 PE .text 段计算 CRC32，与 InitCrcBaseline 注入的基准比对", &DetectCodeCRC32 },
        { 14, L"硬件断点上下文", L"挂起同进程其他线程后 GetThreadContext 读 DR0-DR7", &DetectDrxContext },
        { 15, L"硬件断点 VEH", L"AddVectoredExceptionHandler+RaiseException，回调读 ContextRecord 的 DR", &DetectDrxVEH },
        { 16, L"ScyllaHide 特征", L"检测 PEB 伪造版本 1337、Wow64Transition 以及 ntdll 导出的 inline hook", &DetectScyllaHide },
        { 17, L"路径白名单", L"GetModuleFileNameW 与 InitBenignPath 设置的期望路径前缀比对", &DetectBenignPath },
        { 18, L"内核调试器", L"NtQuerySystemInformation(SystemKernelDebuggerInformation=0x23)，Enabled 且 Present", &DetectKernelDebugger },
        { 19, L"Cheat Engine 进程", L"Toolhelp32Snapshot 枚举进程名，匹配 cheatengine*", &DetectCheatEngine },
        { 20, L"x64dbg/x32dbg 进程", L"Toolhelp32Snapshot 枚举进程名，匹配 x32dbg.exe/x64dbg.exe", &DetectX64dbg },
        { 21, L"火绒剑进程", L"Toolhelp32Snapshot 枚举进程名，匹配 HrSword.exe / HipsMain.exe / Huorong*", &DetectHuorongSword },
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
