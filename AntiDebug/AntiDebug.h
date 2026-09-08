#pragma once

#include <windows.h>

// 检测结果状态。
enum DetectionStatus : int
{
    AD_NOT_DETECTED = 0,     // 未检测到
    AD_DETECTED = 1,         // 检测到
    AD_FAILED = 2,           // 调用失败
    AD_NOT_IMPLEMENTED = 3   // 未实现（预留）
};

struct DetectionItem
{
    int id;                   // 1 起始的编号
    const wchar_t* name;      // 检测项名称
    const wchar_t* principle; // 检测原理说明
    DetectionStatus (*Run)(DWORD* lastError);
};

int GetDetectionCount();
const DetectionItem* GetDetectionItems();

// 1. 读取 PEB.BeingDebugged（x64: gs:[0x60]+2；x86: fs:[0x30]+2）
DetectionStatus DetectBeingDebugged(DWORD* lastError);

// 2. 读取 PEB.NtGlobalFlag（x64 偏移 0xBC，x86 偏移 0x68），低字节 & 0x70 != 0
DetectionStatus DetectNtGlobalFlag(DWORD* lastError);

// 3. 直接调用 kernel32!IsDebuggerPresent
DetectionStatus DetectIsDebuggerPresent(DWORD* lastError);

// 4. 调用 kernel32!CheckRemoteDebuggerPresent(GetCurrentProcess())
DetectionStatus DetectCheckRemoteDebuggerPresent(DWORD* lastError);

// 5. NtQueryInformationProcess(ProcessDebugPort = 7)，端口非 0 即被调试
DetectionStatus DetectDebugPort(DWORD* lastError);

// 6. NtQueryInformationProcess(ProcessDebugObjectHandle = 0x1E)，Vista+
DetectionStatus DetectDebugObjectHandle(DWORD* lastError);

// 7. NtQueryInformationProcess(ProcessDebugFlags = 0x1F)，被调试时返回 0
DetectionStatus DetectDebugFlags(DWORD* lastError);

// 8. 查询父进程名，与白名单比对（explorer/cmd/powershell/WindowsTerminal 等）
DetectionStatus DetectParentProcess(DWORD* lastError);

// 9. 动态解析 ntdll!NtClose，对无效句柄调用，SEH 捕获 STATUS_INVALID_HANDLE
DetectionStatus DetectNtCloseInvalidHandle(DWORD* lastError);

// 10. NtDuplicateObject + NtQueryObject(ObjectTypeInformation=2)，判断类型名为 DebugObject
DetectionStatus DetectDebugObject(DWORD* lastError);

// 11. EnumWindows + GetWindowTextW 匹配调试器窗口名黑名单（避免短词误报）
DetectionStatus DetectWindowDebugger(DWORD* lastError);

// 12. GetTickCount64 前后 Sleep(100)，差值超阈值判定被调试
DetectionStatus DetectTickCountDelta(DWORD* lastError);

// 13. 解析 PE .text 段计算 CRC32，与 InitCrcBaseline 注入的基准比对
DetectionStatus DetectCodeCRC32(DWORD* lastError);

// 14. 挂起同进程其他线程后 GetThreadContext 读 DR0-DR7
DetectionStatus DetectDrxContext(DWORD* lastError);

// 15. AddVectoredExceptionHandler + RaiseException，回调从 ContextRecord 读 DR
DetectionStatus DetectDrxVEH(DWORD* lastError);

// 16. 检测 ScyllaHide：PEB 伪造版本、Wow64Transition、ntdll inline hook
DetectionStatus DetectScyllaHide(DWORD* lastError);

// 17. GetModuleFileNameW 与 InitBenignPath 设置的期望路径前缀比对
DetectionStatus DetectBenignPath(DWORD* lastError);

// 18. NtQuerySystemInformation(SystemKernelDebuggerInformation=0x23)，Enabled 且 Present
DetectionStatus DetectKernelDebugger(DWORD* lastError);

// 19. Toolhelp32Snapshot 枚举进程名，匹配 cheatengine*
DetectionStatus DetectCheatEngine(DWORD* lastError);

// 20. Toolhelp32Snapshot 枚举进程名，匹配 x32dbg.exe / x64dbg.exe
DetectionStatus DetectX64dbg(DWORD* lastError);

// 21. Toolhelp32Snapshot 枚举进程名，匹配 HrSword.exe / HipsMain.exe / Huorong*
DetectionStatus DetectHuorongSword(DWORD* lastError);

// 22. Toolhelp32Snapshot 枚举进程名，匹配 PCHunter*
DetectionStatus DetectPCHunter(DWORD* lastError);

// 供调用方注入 .text CRC32 基准值（第 13 项使用）。
void InitCrcBaseline(DWORD crc);

// 计算当前模块 .text 段 CRC32，供调用方在干净环境下生成基准值。
DWORD ComputeCodeCrc32(DWORD* lastError);

// 设置第 17 项的期望路径前缀；传入空则该项失败。
void InitBenignPath(const wchar_t* path);

// 将第 17 项期望路径设为当前模块所在目录。
void InitDefaultBenignPath();
