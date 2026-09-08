#include "App.h"
#include "AntiDebug.h"

#include <windows.h>
#include <commctrl.h>

#include <excpt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <atomic>

#ifndef LVS_EX_FULLROWSELECT
#define LVS_EX_FULLROWSELECT 0x00000020
#endif

#ifndef LVS_EX_DOUBLEBUFFER
#define LVS_EX_DOUBLEBUFFER 0x00010000
#endif

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Comctl32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace
{
    const wchar_t kMainWindowClass[] = L"AntiDebug.MainWindow";
    const wchar_t kMainWindowTitle[] = L"反调试检测工具";

    // 日志区软上限：超过后从头部丢弃最旧内容，防止多次检测后 Edit 控件文本无限膨胀拖慢 UI。
    constexpr int kLogSoftLimitChars = 32768;

    const int kDefaultWidth = 1600;
    const int kDefaultHeight = 900;
    const int kMinWidth = 1280;
    const int kMinHeight = 720;

    const int kMargin = 12;
    const int kToolbarY = 8;
    const int kToolbarHeight = 26;
    const int kListY = 44;
    const int kLogHeight = 250;
    const int kButtonWidth = 88;
    const int kSummaryWidth = 140;
    const int kLegendWidth = 110;
    const int kLegendGap = 4;

    HINSTANCE g_hInstance = nullptr;
    HWND g_hMainWnd = nullptr;
    HWND g_hBtnStart = nullptr;
    HWND g_hBtnClear = nullptr;
    HWND g_hSummary = nullptr;
    HWND g_hLegendGreen = nullptr;
    HWND g_hLegendRed = nullptr;
    HWND g_hLegendBlue = nullptr;
    HWND g_hListView = nullptr;
    HWND g_hLog = nullptr;
    HFONT g_hFont = nullptr;

    // 跨线程标志统一用原子类型；volatile 既不提供原子性也不提供内存序。
    std::atomic<bool> g_cancel{false};
    std::atomic<bool> g_acceptMessages{false};
    HANDLE g_hThread = nullptr;

    // g_rowStatus 只允许在 UI 线程读写（WM_APP_DETECTION_RESULT / custom draw），无需加锁。
    int g_rowStatus[kDetectionItemCount] = {};

    // 把 lastError 与状态打包进 LPARAM：lastError 占高 62 位，status 占低 2 位。
    LPARAM PackDetectionResult(DWORD lastError, int status)
    {
        ULONGLONG packed = (static_cast<ULONGLONG>(lastError) << 2) | (static_cast<DWORD>(status) & 0x3);
        return static_cast<LPARAM>(packed);
    }

    COLORREF GetStatusColor(int status)
    {
        switch (status)
        {
        case AD_DETECTED:
            return RGB(192, 57, 43);    // #C0392B 红
        case AD_NOT_DETECTED:
            return RGB(46, 125, 50);    // #2E7D32 绿
        case AD_FAILED:
            return RGB(21, 101, 192);   // #1565C0 蓝
        case AD_NOT_IMPLEMENTED:
            return RGB(107, 114, 128);  // #6B7280 灰
        default:
            return RGB(107, 114, 128);  // #6B7280 灰
        }
    }

    const wchar_t* GetStatusText(int status)
    {
        switch (status)
        {
        case AD_DETECTED:
            return L"检测到";
        case AD_FAILED:
            return L"调用失败";
        case AD_NOT_IMPLEMENTED:
            return L"未实现";
        case AD_NOT_DETECTED:
        default:
            return L"未检测到";
        }
    }

    int GetRowStatus(int row)
    {
        if (row < 0 || row >= kDetectionItemCount)
        {
            return AD_NOT_DETECTED;
        }
        return g_rowStatus[row];
    }

    void UpdateSummary()
    {
        int detected = 0;
        int count = GetDetectionCount();
        if (count > kDetectionItemCount)
        {
            count = kDetectionItemCount;
        }
        for (int i = 0; i < count; ++i)
        {
            if (g_rowStatus[i] == AD_DETECTED)
            {
                ++detected;
            }
        }

        wchar_t text[64] = {};
        _snwprintf_s(text, _countof(text), _TRUNCATE, L"已检测到 %d / %d", detected, count);
        ::SetWindowTextW(g_hSummary, text);
    }

    void PostLog(const wchar_t* format, ...)
    {
        SYSTEMTIME st = {};
        ::GetLocalTime(&st);

        wchar_t buffer[1024] = {};
        int prefix = _snwprintf_s(
            buffer,
            _countof(buffer),
            _TRUNCATE,
            L"[%02u:%02u:%02u.%03u] ",
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds);
        if (prefix < 0)
        {
            prefix = 0;
        }

        va_list args;
        va_start(args, format);
        _vsnwprintf_s(buffer + prefix, _countof(buffer) - prefix, _TRUNCATE, format, args);
        va_end(args);

        wchar_t* copy = ::_wcsdup(buffer);
        if (copy != nullptr)
        {
            if (!g_acceptMessages.load() || g_hMainWnd == nullptr || !::PostMessageW(g_hMainWnd, WM_APP_LOG, 0, reinterpret_cast<LPARAM>(copy)))
            {
                ::free(copy);
            }
        }
    }

    bool IsLogScrolledToBottom()
    {
        if (g_hLog == nullptr)
        {
            return true;
        }

        SCROLLINFO si = {};
        si.cbSize = sizeof(si);
        si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
        if (!::GetScrollInfo(g_hLog, SB_VERT, &si))
        {
            return true;
        }

        int maxPos = si.nMax - static_cast<int>(si.nPage);
        if (maxPos < 0)
        {
            maxPos = 0;
        }
        return si.nPos >= maxPos;
    }

    void ClearLog()
    {
        if (g_hLog != nullptr)
        {
            ::SetWindowTextW(g_hLog, L"");
        }
    }

    void AppendLogText(const wchar_t* text)
    {
        if (text == nullptr || g_hLog == nullptr)
        {
            return;
        }

        // 若用户已经向上滚动浏览历史日志，则追加时保持其当前浏览位置，
        // 只有原本就在底部时才自动滚到最新一行。避免拖动滚动条时内容跳动。
        bool autoScroll = IsLogScrolledToBottom();

        // 追加前先做软截断：超过上限时丢弃头部最旧文本，避免文本无限膨胀。
        int length = ::GetWindowTextLengthW(g_hLog);
        if (length > kLogSoftLimitChars)
        {
            const int excess = length - kLogSoftLimitChars;
            ::SendMessageW(g_hLog, EM_SETSEL, 0, excess);
            ::SendMessageW(g_hLog, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L""));
            length = ::GetWindowTextLengthW(g_hLog);
        }

        ::SendMessageW(g_hLog, EM_SETSEL, length, length);
        ::SendMessageW(g_hLog, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text));

        if (autoScroll)
        {
            ::SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
        }
    }

    void ResizeListColumns()
    {
        if (g_hListView == nullptr)
        {
            return;
        }

        RECT rc = {};
        ::GetClientRect(g_hListView, &rc);
        int total = rc.right - rc.left;
        if (total <= 0)
        {
            total = 1;
        }

        int col0 = total * 8 / 100;   // 编号
        int col1 = total * 22 / 100;  // 检测项
        int col2 = total * 14 / 100;  // 状态
        int col3 = total * 12 / 100;  // 错误码
        int col4 = total - col0 - col1 - col2 - col3; // 检测原理
        if (col4 < 80)
        {
            col4 = 80;
        }

        ListView_SetColumnWidth(g_hListView, 0, col0);
        ListView_SetColumnWidth(g_hListView, 1, col1);
        ListView_SetColumnWidth(g_hListView, 2, col2);
        ListView_SetColumnWidth(g_hListView, 3, col3);
        ListView_SetColumnWidth(g_hListView, 4, col4);
    }

    void ResizeLayout(int cx, int cy)
    {
        int listWidth = cx - kMargin * 2;
        if (listWidth < 0)
        {
            listWidth = 0;
        }

        int logY = cy - kMargin - kLogHeight;
        if (logY < kListY + 10)
        {
            logY = kListY + 10;
        }

        int listHeight = logY - kListY - 10;
        if (listHeight < 0)
        {
            listHeight = 0;
        }

        ::MoveWindow(g_hBtnStart, kMargin, kToolbarY, kButtonWidth, kToolbarHeight, TRUE);
        ::MoveWindow(g_hBtnClear, kMargin + kButtonWidth + 8, kToolbarY, kButtonWidth, kToolbarHeight, TRUE);

        int legendX = kMargin + kButtonWidth * 2 + 8 + 14;
        ::MoveWindow(g_hLegendGreen, legendX, kToolbarY, kLegendWidth, kToolbarHeight, TRUE);
        legendX += kLegendWidth + kLegendGap;
        ::MoveWindow(g_hLegendRed, legendX, kToolbarY, kLegendWidth, kToolbarHeight, TRUE);
        legendX += kLegendWidth + kLegendGap;
        ::MoveWindow(g_hLegendBlue, legendX, kToolbarY, kLegendWidth, kToolbarHeight, TRUE);

        ::MoveWindow(g_hSummary, cx - kMargin - kSummaryWidth, kToolbarY + 2, kSummaryWidth, kToolbarHeight, TRUE);
        ::MoveWindow(g_hListView, kMargin, kListY, listWidth, listHeight, TRUE);
        ::MoveWindow(g_hLog, kMargin, logY, listWidth, kLogHeight, TRUE);

        ResizeListColumns();
    }

    void InitListColumns()
    {
        struct ColumnDef
        {
            const wchar_t* text;
            int width;
        };

        const ColumnDef columns[] =
        {
            { L"编号", 60 },
            { L"检测项", 160 },
            { L"状态", 100 },
            { L"错误码", 80 },
            { L"检测原理", 240 },
        };

        for (int i = 0; i < 5; ++i)
        {
            LVCOLUMNW col = {};
            col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
            col.pszText = const_cast<wchar_t*>(columns[i].text);
            col.cx = columns[i].width;
            col.iSubItem = i;
            ListView_InsertColumn(g_hListView, i, &col);
        }
    }

    void ResetList()
    {
        if (g_hListView == nullptr)
        {
            return;
        }

        ListView_DeleteAllItems(g_hListView);

        const DetectionItem* items = GetDetectionItems();
        int count = GetDetectionCount();
        if (count > kDetectionItemCount)
        {
            count = kDetectionItemCount;
        }

        for (int i = 0; i < count; ++i)
        {
            wchar_t idText[16] = {};
            _snwprintf_s(idText, _countof(idText), _TRUNCATE, L"%d", items[i].id);

            LVITEMW item = {};
            item.mask = LVIF_TEXT;
            item.iItem = i;
            item.iSubItem = 0;
            item.pszText = idText;

            int index = ListView_InsertItem(g_hListView, &item);
            ListView_SetItemText(g_hListView, index, 1, const_cast<wchar_t*>(items[i].name));
            ListView_SetItemText(g_hListView, index, 2, const_cast<wchar_t*>(L""));
            ListView_SetItemText(g_hListView, index, 3, const_cast<wchar_t*>(L""));
            ListView_SetItemText(g_hListView, index, 4, const_cast<wchar_t*>(items[i].principle));
        }

        for (int i = 0; i < kDetectionItemCount; ++i)
        {
            g_rowStatus[i] = AD_NOT_DETECTED;
        }

        UpdateSummary();
    }

    void CreateChildControls(HWND parent)
    {
        const DWORD buttonStyle = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON;
        const DWORD legendStyle = WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE;

        g_hBtnStart = ::CreateWindowExW(
            0,
            L"BUTTON",
            L"开始检测",
            buttonStyle,
            0, 0, 0, 0,
            parent,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_BTN_START)),
            g_hInstance,
            nullptr);

        g_hBtnClear = ::CreateWindowExW(
            0,
            L"BUTTON",
            L"清除日志",
            buttonStyle,
            0, 0, 0, 0,
            parent,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_BTN_CLEAR)),
            g_hInstance,
            nullptr);

        wchar_t summaryText[64] = {};
        _snwprintf_s(summaryText, _countof(summaryText), _TRUNCATE, L"已检测到 0 / %d", GetDetectionCount());
        g_hSummary = ::CreateWindowExW(
            0,
            L"STATIC",
            summaryText,
            WS_CHILD | WS_VISIBLE | SS_RIGHT,
            0, 0, 0, 0,
            parent,
            nullptr,
            g_hInstance,
            nullptr);

        g_hLegendGreen = ::CreateWindowExW(
            0,
            L"STATIC",
            L"● 未检测到",
            legendStyle,
            0, 0, 0, 0,
            parent,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LEGEND_GREEN)),
            g_hInstance,
            nullptr);

        g_hLegendRed = ::CreateWindowExW(
            0,
            L"STATIC",
            L"● 检测到",
            legendStyle,
            0, 0, 0, 0,
            parent,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LEGEND_RED)),
            g_hInstance,
            nullptr);

        g_hLegendBlue = ::CreateWindowExW(
            0,
            L"STATIC",
            L"● 调用失败",
            legendStyle,
            0, 0, 0, 0,
            parent,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LEGEND_BLUE)),
            g_hInstance,
            nullptr);

        g_hListView = ::CreateWindowExW(
            0,
            WC_LISTVIEWW,
            L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
            0, 0, 0, 0,
            parent,
            nullptr,
            g_hInstance,
            nullptr);

        g_hLog = ::CreateWindowExW(
            0,
            L"EDIT",
            L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY | WS_VSCROLL | WS_HSCROLL,
            0, 0, 0, 0,
            parent,
            nullptr,
            g_hInstance,
            nullptr);

        // 放开默认文本长度限制，避免日志较多时被截断。
        ::SendMessageW(g_hLog, EM_SETLIMITTEXT, 0x7FFFFFFE, 0);

        ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

        g_hFont = reinterpret_cast<HFONT>(::GetStockObject(DEFAULT_GUI_FONT));
        if (g_hFont != nullptr)
        {
            ::SendMessageW(g_hBtnStart, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFont), TRUE);
            ::SendMessageW(g_hBtnClear, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFont), TRUE);
            ::SendMessageW(g_hSummary, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFont), TRUE);
            ::SendMessageW(g_hLegendGreen, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFont), TRUE);
            ::SendMessageW(g_hLegendRed, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFont), TRUE);
            ::SendMessageW(g_hLegendBlue, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFont), TRUE);
            ::SendMessageW(g_hListView, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFont), TRUE);
            ::SendMessageW(g_hLog, WM_SETFONT, reinterpret_cast<WPARAM>(g_hFont), TRUE);
        }
    }

    void UpdateRow(int row, int status, DWORD lastError)
    {
        if (row < 0 || row >= kDetectionItemCount || g_hListView == nullptr)
        {
            return;
        }

        g_rowStatus[row] = status;

        ListView_SetItemText(g_hListView, row, 2, const_cast<wchar_t*>(GetStatusText(status)));

        wchar_t code[32] = {};
        if (status == AD_FAILED)
        {
            _snwprintf_s(code, _countof(code), _TRUNCATE, L"0x%08lX", lastError);
        }
        else
        {
            _snwprintf_s(code, _countof(code), _TRUNCATE, L"0");
        }
        ListView_SetItemText(g_hListView, row, 3, code);

        ListView_RedrawItems(g_hListView, row, row);
        UpdateSummary();
    }

    void OnDetectionDone()
    {
        if (g_hThread != nullptr)
        {
            ::CloseHandle(g_hThread);
            g_hThread = nullptr;
        }

        ::EnableWindow(g_hBtnStart, TRUE);
        UpdateSummary();
        PostLog(L"检测完成，共 %d 项。\r\n", GetDetectionCount());
    }

    void StartDetection()
    {
        if (g_hThread != nullptr)
        {
            return;
        }

        ResetList();
        g_cancel.store(false);

        PostLog(L"开始检测，共 %d 项。\r\n", GetDetectionCount());

        g_hThread = ::CreateThread(nullptr, 0, DetectionThreadProc, nullptr, 0, nullptr);
        if (g_hThread == nullptr)
        {
            DWORD err = ::GetLastError();
            PostLog(L"创建检测线程失败，错误码：%lu\r\n", err);
            ::EnableWindow(g_hBtnStart, TRUE);
            return;
        }

        ::EnableWindow(g_hBtnStart, FALSE);
    }

    LRESULT HandleCustomDraw(NMHDR* header)
    {
        NMLVCUSTOMDRAW* customDraw = reinterpret_cast<NMLVCUSTOMDRAW*>(header);
        switch (customDraw->nmcd.dwDrawStage)
        {
        case CDDS_PREPAINT:
            return CDRF_NOTIFYITEMDRAW;

        case CDDS_ITEMPREPAINT:
        {
            int row = static_cast<int>(customDraw->nmcd.dwItemSpec);
            COLORREF color = GetStatusColor(GetRowStatus(row));
            customDraw->clrText = color;
            customDraw->clrTextBk = ::GetSysColor(COLOR_WINDOW);
            return CDRF_NOTIFYSUBITEMDRAW;
        }

        case CDDS_SUBITEM | CDDS_ITEMPREPAINT:
        {
            int row = static_cast<int>(customDraw->nmcd.dwItemSpec);
            COLORREF color = GetStatusColor(GetRowStatus(row));
            customDraw->clrText = color;
            customDraw->clrTextBk = ::GetSysColor(COLOR_WINDOW);
            return CDRF_DODEFAULT;
        }

        default:
            return CDRF_DODEFAULT;
        }
    }

    LRESULT HandleCtlColorStatic(HDC hdc, HWND hwnd)
    {
        // 只读多行 EDIT 也会发送 WM_CTLCOLORSTATIC。
        // 必须单独处理：保持不透明背景，否则滚动/重绘时文字会像墨水一样互相覆盖。
        if (hwnd == g_hLog)
        {
            ::SetTextColor(hdc, ::GetSysColor(COLOR_WINDOWTEXT));
            ::SetBkColor(hdc, ::GetSysColor(COLOR_WINDOW));
            ::SetBkMode(hdc, OPAQUE);
            return reinterpret_cast<LRESULT>(::GetSysColorBrush(COLOR_WINDOW));
        }

        if (hwnd == g_hLegendGreen)
        {
            ::SetTextColor(hdc, RGB(46, 125, 50)); // #2E7D32 绿
        }
        else if (hwnd == g_hLegendRed)
        {
            ::SetTextColor(hdc, RGB(192, 57, 43)); // #C0392B 红
        }
        else if (hwnd == g_hLegendBlue)
        {
            ::SetTextColor(hdc, RGB(21, 101, 192)); // #1565C0 蓝
        }

        ::SetBkMode(hdc, TRANSPARENT);
        return reinterpret_cast<LRESULT>(::GetSysColorBrush(COLOR_BTNFACE));
    }

    LRESULT HandleCtlColorEdit(HDC hdc, HWND hwnd)
    {
        if (hwnd == g_hLog)
        {
            ::SetTextColor(hdc, ::GetSysColor(COLOR_WINDOWTEXT));
            ::SetBkColor(hdc, ::GetSysColor(COLOR_WINDOW));
            ::SetBkMode(hdc, OPAQUE);
            return reinterpret_cast<LRESULT>(::GetSysColorBrush(COLOR_WINDOW));
        }

        return reinterpret_cast<LRESULT>(::GetSysColorBrush(COLOR_WINDOW));
    }
}

LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
        g_hMainWnd = hWnd;
        g_acceptMessages.store(true);
        CreateChildControls(hWnd);
        InitListColumns();
        ResetList();

        {
            // 立即按当前客户区布局一次，避免某些情况下 WM_SIZE 尚未触发导致控件保持 0 尺寸。
            RECT rc = {};
            ::GetClientRect(hWnd, &rc);
            ResizeLayout(rc.right - rc.left, rc.bottom - rc.top);
        }
        return 0;

    case WM_SIZE:
        ResizeLayout(static_cast<int>(LOWORD(lParam)), static_cast<int>(HIWORD(lParam)));
        return 0;

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
        mmi->ptMinTrackSize.x = kMinWidth;
        mmi->ptMinTrackSize.y = kMinHeight;
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BTN_START:
            StartDetection();
            return 0;

        case IDC_BTN_CLEAR:
            ClearLog();
            return 0;

        default:
            break;
        }
        break;

    case WM_APP_DETECTION_RESULT:
    {
        // lastError 由工作线程随消息打包（高 62 位），UI 线程无需再访问共享数组。
        const ULONGLONG packed = static_cast<ULONGLONG>(lParam);
        const DWORD lastError = static_cast<DWORD>(packed >> 2);
        const int status = static_cast<int>(packed & 0x3);
        UpdateRow(static_cast<int>(wParam), status, lastError);
        return 0;
    }

    case WM_APP_DETECTION_DONE:
        OnDetectionDone();
        return 0;

    case WM_CTLCOLORSTATIC:
        return HandleCtlColorStatic(reinterpret_cast<HDC>(wParam), reinterpret_cast<HWND>(lParam));

    case WM_CTLCOLOREDIT:
        return HandleCtlColorEdit(reinterpret_cast<HDC>(wParam), reinterpret_cast<HWND>(lParam));

    case WM_APP_LOG:
        AppendLogText(reinterpret_cast<const wchar_t*>(lParam));
        ::free(reinterpret_cast<void*>(lParam));
        return 0;

    case WM_NOTIFY:
    {
        NMHDR* header = reinterpret_cast<NMHDR*>(lParam);
        if (header != nullptr && header->hwndFrom == g_hListView && header->code == NM_CUSTOMDRAW)
        {
            return HandleCustomDraw(header);
        }
        break;
    }

    case WM_CLOSE:
        g_acceptMessages.store(false);
        if (g_hThread != nullptr)
        {
            g_cancel.store(true);
            ::WaitForSingleObject(g_hThread, 5000);
            ::CloseHandle(g_hThread);
            g_hThread = nullptr;
        }
        {
            MSG pending = {};
            while (::PeekMessageW(&pending, hWnd, WM_APP_LOG, WM_APP_LOG, PM_REMOVE))
            {
                ::free(reinterpret_cast<void*>(pending.lParam));
            }
            while (::PeekMessageW(&pending, hWnd, WM_APP_DETECTION_RESULT, WM_APP_DETECTION_DONE, PM_REMOVE))
            {
            }
        }
        ::DestroyWindow(hWnd);
        return 0;

    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;

    default:
        break;
    }

    return ::DefWindowProcW(hWnd, message, wParam, lParam);
}

DWORD WINAPI DetectionThreadProc(LPVOID /*lpParameter*/)
{
    const DetectionItem* items = GetDetectionItems();
    int count = GetDetectionCount();
    if (count > kDetectionItemCount)
    {
        count = kDetectionItemCount;
    }

    for (int i = 0; i < count; ++i)
    {
        if (g_cancel.load())
        {
            break;
        }

        const DetectionItem& item = items[i];
        PostLog(L"[%d/%d] 开始：%s\r\n", i + 1, count, item.name);

        DWORD lastError = 0;
        DetectionStatus status = AD_FAILED;

        __try
        {
            status = item.Run(&lastError);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = AD_FAILED;
            lastError = ::GetExceptionCode();
            PostLog(L"[%d/%d] 异常：%s，异常代码 0x%08lX\r\n", i + 1, count, item.name, lastError);
        }

        if (g_acceptMessages.load() && g_hMainWnd != nullptr)
        {
            ::PostMessageW(
                g_hMainWnd,
                WM_APP_DETECTION_RESULT,
                static_cast<WPARAM>(i),
                PackDetectionResult(lastError, status));
        }

        PostLog(
            L"[%d/%d] 结束：%s，状态=%d，错误码=0x%08lX\r\n",
            i + 1,
            count,
            item.name,
            static_cast<int>(status),
            lastError);
    }

    if (g_acceptMessages.load() && g_hMainWnd != nullptr)
    {
        ::PostMessageW(g_hMainWnd, WM_APP_DETECTION_DONE, 0, 0);
    }
    return 0;
}

_Use_decl_annotations_
int APIENTRY wWinMain(HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    PWSTR lpCmdLine,
    int nShowCmd)
{
    g_hInstance = hInstance;

    // 在创建任何窗口前声明系统 DPI 感知，避免高分屏下被系统按位图拉伸导致文字模糊。
    ::SetProcessDPIAware();

    // UI 行状态数组为编译期固定容量；检测项超过容量时静默截断会丢结果，直接拒绝启动。
    if (GetDetectionCount() > kDetectionItemCount)
    {
        ::MessageBoxW(nullptr, L"检测项数量超过 UI 容量，请同步增大 kDetectionItemCount。", L"反调试检测工具", MB_ICONERROR);
        return 1;
    }

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    ::InitCommonControlsEx(&icc);

    DWORD crcError = 0;
    DWORD crc = ComputeCodeCrc32(&crcError);
    if (crcError == 0)
    {
        InitCrcBaseline(crc);
    }
    InitDefaultBenignPath();

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ::GetSysColorBrush(COLOR_BTNFACE);
    wc.lpszClassName = kMainWindowClass;
    wc.hIcon = ::LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm = ::LoadIconW(nullptr, IDI_APPLICATION);

    if (!::RegisterClassExW(&wc))
    {
        return 1;
    }

    RECT workArea = {};
    ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
    int x = workArea.left + ((workArea.right - workArea.left) - kDefaultWidth) / 2;
    int y = workArea.top + ((workArea.bottom - workArea.top) - kDefaultHeight) / 2;
    if (x < 0)
    {
        x = 0;
    }
    if (y < 0)
    {
        y = 0;
    }

    HWND hwnd = ::CreateWindowExW(
        0,
        kMainWindowClass,
        kMainWindowTitle,
        WS_OVERLAPPEDWINDOW,
        x,
        y,
        kDefaultWidth,
        kDefaultHeight,
        nullptr,
        nullptr,
        hInstance,
        nullptr);
    if (hwnd == nullptr)
    {
        return 1;
    }

    ::ShowWindow(hwnd, nShowCmd);
    ::UpdateWindow(hwnd);

    MSG msg = {};
    while (::GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        ::TranslateMessage(&msg);
        ::DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}
