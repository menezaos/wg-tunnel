#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winhttp.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>

#define IDC_STATUS  101
#define IDC_SERVER  102
#define IDC_TOKEN   103
#define IDC_CONNECT 104
#define IDC_ERROR   105
#define TIMER_ID    1

#define TUNNEL_NAME L"wgtunnel"
#define WG_EXE      L"C:\\Program Files\\WireGuard\\wireguard.exe"

static HWND g_status, g_server, g_token, g_connect, g_error;
static BOOL g_connected = FALSE;

static void GetConfigDir(WCHAR *out, int len) {
    WCHAR base[MAX_PATH];
    GetEnvironmentVariable(L"APPDATA", base, MAX_PATH);
    swprintf(out, len, L"%ls\\WGTunnel", base);
}

static void LoadConfig(WCHAR *server, int sLen, WCHAR *token, int tLen) {
    WCHAR dir[MAX_PATH], ini[MAX_PATH];
    GetConfigDir(dir, MAX_PATH);
    swprintf(ini, MAX_PATH, L"%ls\\config.ini", dir);
    GetPrivateProfileString(L"config", L"server_url", L"", server, sLen, ini);
    GetPrivateProfileString(L"config", L"agent_token", L"", token, tLen, ini);
}

static void SaveConfig(const WCHAR *server, const WCHAR *token) {
    WCHAR dir[MAX_PATH], ini[MAX_PATH];
    GetConfigDir(dir, MAX_PATH);
    swprintf(ini, MAX_PATH, L"%ls\\config.ini", dir);
    CreateDirectory(dir, NULL);
    WritePrivateProfileString(L"config", L"server_url", server, ini);
    WritePrivateProfileString(L"config", L"agent_token", token, ini);
}

static BOOL WireGuardInstalled(void) {
    return GetFileAttributes(WG_EXE) != INVALID_FILE_ATTRIBUTES;
}

static SC_HANDLE OpenTunnelService(DWORD access) {
    WCHAR svcName[64];
    swprintf(svcName, 64, L"WireGuardTunnel$%ls", TUNNEL_NAME);
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return NULL;
    SC_HANDLE hSvc = OpenService(hSCM, svcName, access);
    CloseServiceHandle(hSCM);
    return hSvc;
}

static BOOL TunnelServiceExists(void) {
    SC_HANDLE hSvc = OpenTunnelService(SERVICE_QUERY_STATUS);
    if (!hSvc) return FALSE;
    CloseServiceHandle(hSvc);
    return TRUE;
}

static BOOL CheckConnected(void) {
    SC_HANDLE hSvc = OpenTunnelService(SERVICE_QUERY_STATUS);
    if (!hSvc) return FALSE;
    SERVICE_STATUS ss;
    BOOL running = QueryServiceStatus(hSvc, &ss) &&
                   ss.dwCurrentState == SERVICE_RUNNING;
    CloseServiceHandle(hSvc);
    return running;
}

static BOOL RunWG(const WCHAR *arg1, const WCHAR *arg2) {
    WCHAR cmd[MAX_PATH + 512];
    swprintf(cmd, MAX_PATH + 512, L"\"%ls\" %ls \"%ls\"", WG_EXE, arg1, arg2);
    STARTUPINFO si = {sizeof(si)};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    if (!CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return FALSE;
    WaitForSingleObject(pi.hProcess, 10000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

static BOOL ParseURL(const WCHAR *url, BOOL *https, WCHAR *host, int hostLen,
                     INTERNET_PORT *port, WCHAR *path, int pathLen) {
    const WCHAR *p = url;
    if (wcsncmp(p, L"https://", 8) == 0) { *https = TRUE;  p += 8; *port = 443; }
    else if (wcsncmp(p, L"http://", 7) == 0) { *https = FALSE; p += 7; *port = 80;  }
    else return FALSE;

    const WCHAR *hostStart = p;
    while (*p && *p != L':' && *p != L'/') p++;
    int hLen = (int)(p - hostStart);
    if (hLen == 0 || hLen >= hostLen) return FALSE;
    wcsncpy(host, hostStart, hLen);
    host[hLen] = 0;

    if (*p == L':') {
        p++;
        *port = 0;
        while (*p >= L'0' && *p <= L'9') { *port = *port * 10 + (*p - L'0'); p++; }
    }

    if (*p == L'/') { wcsncpy(path, p, pathLen - 1); path[pathLen - 1] = 0; }
    else path[0] = 0;
    return TRUE;
}

static char *FetchWGConfig(const WCHAR *serverURL, const WCHAR *token, WCHAR *errOut, int errLen) {
    BOOL https = FALSE;
    WCHAR host[256] = {0}, urlPath[1024] = {0};
    INTERNET_PORT port = 80;

    if (!ParseURL(serverURL, &https, host, 256, &port, urlPath, 1024)) {
        swprintf(errOut, errLen, L"URL inválida: [%ls]", serverURL);
        return NULL;
    }

    WCHAR path[1024];
    if (!urlPath[0] || (urlPath[0] == L'/' && !urlPath[1]))
        swprintf(path, 1024, L"/api/agent/wgconfig");
    else
        swprintf(path, 1024, L"%ls/api/agent/wgconfig", urlPath);

    DWORD secFlags = https ? WINHTTP_FLAG_SECURE : 0;

    HINTERNET hSess = WinHttpOpen(L"WGTunnelClient/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSess) { swprintf(errOut, errLen, L"WinHTTP falhou"); return NULL; }

    HINTERNET hConn = WinHttpConnect(hSess, host, port, 0);
    if (!hConn) {
        WinHttpCloseHandle(hSess);
        swprintf(errOut, errLen, L"Não foi possível conectar ao servidor");
        return NULL;
    }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path, NULL, NULL, NULL, secFlags);
    if (!hReq) {
        WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        swprintf(errOut, errLen, L"Falha ao criar requisição");
        return NULL;
    }

    WCHAR auth[512];
    swprintf(auth, 512, L"Authorization: Bearer %ls", token);
    WinHttpAddRequestHeaders(hReq, auth, -1L, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hReq, NULL, 0, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(hReq, NULL)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        swprintf(errOut, errLen, L"Erro de conexão com o servidor");
        return NULL;
    }

    DWORD status = 0, ssz = sizeof(status);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &status, &ssz, NULL);

    if (status == 401) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        swprintf(errOut, errLen, L"Token inválido ou não autorizado");
        return NULL;
    }
    if (status != 200) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        swprintf(errOut, errLen, L"Servidor retornou %lu", status);
        return NULL;
    }

    char *body = NULL;
    size_t bodyLen = 0;
    DWORD avail, nread;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail) {
        char *buf = malloc(avail + 1);
        WinHttpReadData(hReq, buf, avail, &nread);
        body = realloc(body, bodyLen + nread + 1);
        memcpy(body + bodyLen, buf, nread);
        bodyLen += nread;
        body[bodyLen] = 0;
        free(buf);
    }

    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
    if (!body) swprintf(errOut, errLen, L"Resposta vazia do servidor");
    return body;
}

static void RefreshStatus(void) {
    g_connected = CheckConnected();
    SetWindowText(g_status, g_connected ? L"● Conectado" : L"● Desconectado");
    SetWindowText(g_connect, g_connected ? L"Desconectar" : L"Conectar");
    InvalidateRect(g_status, NULL, TRUE);
}

typedef struct { WCHAR server[512]; WCHAR token[256]; } WorkArgs;

static DWORD WINAPI ConnectThread(LPVOID p) {
    WorkArgs *a = (WorkArgs *)p;
    WCHAR err[512] = {0};

    if (!WireGuardInstalled()) {
        SetWindowText(g_error, L"WireGuard não encontrado. Baixe e instale em wireguard.com.");
        goto done;
    }

    char *conf = FetchWGConfig(a->server, a->token, err, 512);
    if (!conf) { SetWindowText(g_error, err); goto done; }

    WCHAR dir[MAX_PATH], confPath[MAX_PATH];
    GetConfigDir(dir, MAX_PATH);
    swprintf(confPath, MAX_PATH, L"%ls\\wgtunnel.conf", dir);
    CreateDirectory(dir, NULL);

    HANDLE hf = CreateFile(confPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        free(conf);
        SetWindowText(g_error, L"Não foi possível salvar a config.");
        goto done;
    }
    DWORD w;
    WriteFile(hf, conf, (DWORD)strlen(conf), &w, NULL);
    CloseHandle(hf);
    free(conf);

    if (TunnelServiceExists()) {
        RunWG(L"/uninstalltunnelservice", TUNNEL_NAME);
        Sleep(500);
    }

    if (!RunWG(L"/installtunnelservice", confPath)) {
        SetWindowText(g_error, L"Falha ao instalar tunnel. Execute como Administrador.");
        goto done;
    }
    SetWindowText(g_error, L"");

done:
    free(a);
    EnableWindow(g_connect, TRUE);
    RefreshStatus();
    return 0;
}

static DWORD WINAPI DisconnectThread(LPVOID p) {
    (void)p;
    if (!RunWG(L"/uninstalltunnelservice", TUNNEL_NAME))
        SetWindowText(g_error, L"Falha ao desconectar. Execute como Administrador.");
    else
        SetWindowText(g_error, L"");
    EnableWindow(g_connect, TRUE);
    RefreshStatus();
    return 0;
}

static void ApplyFont(HWND parent, HFONT hFont) {
    HWND child = GetWindow(parent, GW_CHILD);
    while (child) {
        SendMessage(child, WM_SETFONT, (WPARAM)hFont, TRUE);
        child = GetWindow(child, GW_HWNDNEXT);
    }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HFONT hFont;

    switch (msg) {
    case WM_CREATE: {
        hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        int x = 16, y = 14, W = 414;

        g_status = CreateWindow(L"STATIC", L"● Desconectado",
            WS_CHILD|WS_VISIBLE, x, y, W, 20, hwnd, (HMENU)IDC_STATUS, NULL, NULL);
        y += 28;

        CreateWindow(L"STATIC", L"", WS_CHILD|WS_VISIBLE|SS_ETCHEDHORZ,
            x, y, W, 2, hwnd, NULL, NULL, NULL);
        y += 10;

        CreateWindow(L"STATIC", L"Servidor URL", WS_CHILD|WS_VISIBLE,
            x, y, W, 20, hwnd, NULL, NULL, NULL);
        y += 22;

        g_server = CreateWindow(L"EDIT", L"",
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
            x, y, W, 24, hwnd, (HMENU)IDC_SERVER, NULL, NULL);
        y += 32;

        CreateWindow(L"STATIC", L"Agent Token", WS_CHILD|WS_VISIBLE,
            x, y, W, 20, hwnd, NULL, NULL, NULL);
        y += 22;

        g_token = CreateWindow(L"EDIT", L"",
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|ES_PASSWORD,
            x, y, W, 24, hwnd, (HMENU)IDC_TOKEN, NULL, NULL);
        y += 32;

        CreateWindow(L"STATIC", L"", WS_CHILD|WS_VISIBLE|SS_ETCHEDHORZ,
            x, y, W, 2, hwnd, NULL, NULL, NULL);
        y += 10;

        g_connect = CreateWindow(L"BUTTON", L"Conectar",
            WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
            x, y, W, 32, hwnd, (HMENU)IDC_CONNECT, NULL, NULL);
        y += 40;

        g_error = CreateWindow(L"STATIC", L"",
            WS_CHILD|WS_VISIBLE|SS_LEFT,
            x, y, W, 60, hwnd, (HMENU)IDC_ERROR, NULL, NULL);

        ApplyFont(hwnd, hFont);

        WCHAR server[512], token[256];
        LoadConfig(server, 512, token, 256);
        SetWindowText(g_server, server);
        SetWindowText(g_token, token);

        SetTimer(hwnd, TIMER_ID, 5000, NULL);
        RefreshStatus();
        break;
    }

    case WM_TIMER:
        if (wParam == TIMER_ID) RefreshStatus();
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_CONNECT && IsWindowEnabled(g_connect)) {
            SetWindowText(g_error, L"");
            EnableWindow(g_connect, FALSE);

            if (g_connected) {
                SetWindowText(g_connect, L"Desconectando...");
                CreateThread(NULL, 0, DisconnectThread, NULL, 0, NULL);
            } else {
                WCHAR server[512], token[256];
                GetWindowText(g_server, server, 512);
                GetWindowText(g_token, token, 256);

                if (!server[0] || !token[0]) {
                    SetWindowText(g_error, L"Preencha o servidor e o token.");
                    EnableWindow(g_connect, TRUE);
                    break;
                }

                SaveConfig(server, token);

                WorkArgs *a = malloc(sizeof(WorkArgs));
                swprintf(a->server, 512, L"%ls", server);
                swprintf(a->token, 256, L"%ls", token);

                SetWindowText(g_connect, L"Conectando...");
                CreateThread(NULL, 0, ConnectThread, a, 0, NULL);
            }
        }
        break;

    case WM_CTLCOLORSTATIC: {
        HWND hCtrl = (HWND)lParam;
        if (hCtrl == g_status || hCtrl == g_error) {
            HDC hdc = (HDC)wParam;
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, (hCtrl == g_status && g_connected)
                ? RGB(0, 128, 0) : RGB(192, 0, 0));
            return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
        }
        break;
    }

    case WM_DESTROY:
        KillTimer(hwnd, TIMER_ID);
        PostQuitMessage(0);
        break;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE prev, LPWSTR cmd, int show) {
    (void)prev; (void)cmd;

    WNDCLASS wc = {0};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = L"WGTunnelClient";
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClass(&wc);

    RECT rc = {0, 0, 446, 310};
    AdjustWindowRect(&rc, WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX, FALSE);

    HWND hwnd = CreateWindow(L"WGTunnelClient", L"WG Tunnel",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        NULL, NULL, hInst, NULL);

    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
