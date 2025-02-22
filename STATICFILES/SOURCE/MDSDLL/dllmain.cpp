#define _CRT_SECURE_NO_DEPRECATE
#include <String.h>
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>

char szSyncNameS[MAX_PATH] = "Local\\Semaphore:VIPER\0";
char szSyncNameE[MAX_PATH] = "Local\\Event:VIPER\0";

void inline_bzero(void* p, size_t l)
{
	BYTE* q = (BYTE*)p;
	size_t x = 0;
	for (x = 0; x < l; x++)
		*(q++) = 0x00;
}

extern "C" __declspec(dllexport)
void Run(
	HWND hwnd,        // handle to owner window   
	HINSTANCE hinst,  // instance handle for the DLL   
	LPTSTR lpCmdLine, // string the DLL will parse   
	int nCmdShow      // show state   
)
{

	char path[MAX_PATH];

	HMODULE hm = NULL;

	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
		GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCWSTR)&Run, &hm) == 0)
	{
		int ret = GetLastError();
		fprintf(stderr, "GetModuleHandle failed, error = %d\n", ret);
		// Return or however you want to handle an error.
	}
	GetModuleFileNameA(hm, path, MAX_PATH);
}


void start_loader() {

	STARTUPINFO si;
	inline_bzero(&si, sizeof(si));
	si.cb = sizeof(si);

	char path[MAX_PATH];
	char cmd[MAX_PATH];
	char cmdmutex[MAX_PATH];
	STARTUPINFOA  startup_info;
	PROCESS_INFORMATION process_information;

	HMODULE hm = NULL;

	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
		GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCWSTR)&Run, &hm) == 0)
	{
		int ret = GetLastError();
		fprintf(stderr, "GetModuleHandle failed, error = %d\n", ret);

	}
	ZeroMemory(&startup_info, sizeof(startup_info));
	startup_info.cb = sizeof(startup_info);
	ZeroMemory(&process_information, sizeof(process_information));
	GetModuleFileNameA(hm, path, MAX_PATH);

	char drive[5];
	char dir[MAX_PATH];
	char filename[MAX_PATH];
	char fileext[10];
	_splitpath(path, drive, dir, filename, fileext);

	cmd[0] = '\0';
	strcat(cmd, drive);
	strcat(cmd, dir);
	strcat(cmd, filename);
	strcat(cmd, ".exe");
	cmdmutex[0] = '\0';
	strcat(cmdmutex, drive);
	strcat(cmdmutex, dir);
	strcat(cmdmutex, filename);
	strcat(cmdmutex, ".exe mutex");
	if (CreateProcessA(cmd, cmdmutex, NULL, NULL, TRUE, 0, NULL, NULL, &startup_info, &process_information) == 0) {
		return;
	}
	//WaitForSingleObject(process_information.hProcess, -1);
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		start_loader();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;

	}
	return TRUE;
}