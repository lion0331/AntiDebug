#pragma once

#include <windows.h>

// 与 AntiDebug.cpp 中 GetDetectionCount() 保持一致（22 项全部实现）。
constexpr int kDetectionItemCount = 22;

constexpr UINT WM_APP_DETECTION_RESULT = WM_APP + 1; // wParam=行号, lParam=DetectionStatus
constexpr UINT WM_APP_DETECTION_DONE = WM_APP + 2;   // 全部完成
constexpr UINT WM_APP_LOG = WM_APP + 3;              // lParam=wcsdup(text)，接收方负责 free

constexpr int IDC_BTN_START = 1001;
constexpr int IDC_BTN_CLEAR = 1002;
constexpr int IDC_LEGEND_GREEN = 1003;
constexpr int IDC_LEGEND_RED = 1004;
constexpr int IDC_LEGEND_BLUE = 1005;

int WINAPI wWinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ PWSTR lpCmdLine,
    _In_ int nShowCmd);
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
DWORD WINAPI DetectionThreadProc(LPVOID lpParameter);
