#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <psapi.h>

typedef enum { ThreadHideFromDebugger = 0x11 } THREADINFOCLASS;

typedef NTSTATUS(WINAPI *NtQueryInformationThread_t)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI *NtSetInformationThread_t)(HANDLE, THREADINFOCLASS, PVOID, ULONG);

VOID ThreadMain(LPVOID p);
LPSTR GetMutexString();

VOID WINAPI init_antidbg(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
	//Deobfuscate our mutex and lock it so our child doesnt execute this TLS callback.
	unsigned char s[] =
	{

		0x9d, 0x3, 0x3c, 0xec, 0xf0, 0x8b, 0xb5, 0x5,
		0xe2, 0x2a, 0x87, 0x5, 0x64, 0xe4, 0xf8, 0xe7,
		0x64, 0x29, 0xd2, 0x6, 0xad, 0x29, 0x9a, 0xe0,
		0xea, 0xf9, 0x2, 0x7d, 0x31, 0x72, 0xf7, 0x33,
		0x13, 0x83, 0xb, 0x8f, 0xae, 0x2c, 0xa7, 0x2a,
		0x95
	};

	for (unsigned int m = 0; m < sizeof(s); ++m)
	{
		unsigned char c = s[m];
		c = (c >> 0x7) | (c << 0x1);
		c ^= m;
		c = (c >> 0x5) | (c << 0x3);
		c += 0xa9;
		c = ~c;
		c += 0xd6;
		c = -c;
		c += m;
		c = ~c;
		c = (c >> 0x5) | (c << 0x3);
		c -= m;
		c = ~c;
		c += m;
		c ^= m;
		c += m;
		s[m] = c;
	}

	HANDLE hMutex = CreateMutexA(NULL, TRUE, s);

	// We don't want to empty the working set of our child process, it's not neccessary as it has a debugger attached already.
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		return;
	}

	/*
		CODE DESCRIPTION:
		The following code is reponsible for preventing the debugger to attach on parent process at runtime.
	*/
	SIZE_T min, max;
	SYSTEM_INFO si = { 0 };

	GetSystemInfo(&si);

	K32EmptyWorkingSet(GetCurrentProcess());

	void *p = NULL;
	while (p = VirtualAllocEx(GetCurrentProcess(), NULL, si.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS))
	{
		if (p == NULL)
			break;
	}
	/*
		DESCRIPTION END
	*/


	/*
		CODE DESCRIPTION:
		The following code is responsible for handling the application launch inside a debbuger and invoking a crash.
	*/
	NtQueryInformationThread_t fnNtQueryInformationThread = NULL;
	NtSetInformationThread_t fnNtSetInformationThread = NULL;

	DWORD dwThreadId = 0;
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadMain, NULL, 0, 0, &dwThreadId);

	HMODULE hDLL = LoadLibrary("ntdll.dll");
	if (!hDLL) return -1;

	fnNtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(hDLL, "NtQueryInformationThread");
	fnNtSetInformationThread = (NtSetInformationThread_t)GetProcAddress(hDLL, "NtSetInformationThread");

	if (!fnNtQueryInformationThread || !fnNtSetInformationThread)
		return -1;

	ULONG lHideThread = 1, lRet = 0;

	fnNtSetInformationThread(hThread, ThreadHideFromDebugger, &lHideThread, sizeof(lHideThread));
	fnNtQueryInformationThread(hThread, ThreadHideFromDebugger, &lHideThread, sizeof(lHideThread), &lRet);
	/*
		DESCRIPTION END
	*/
}


// Usually what happens is that person who does the analysis doesn't have a breakpoint set for TLS.
// (It's not set ON by default in x64dbg)
#pragma comment(linker, "/INCLUDE:__tls_used") // We want to include TLS Data Directory structure in our program
#pragma data_seg(push)
#pragma data_seg(".CRT$XLAA")
EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback1 = init_antidbg; // This will execute before entry point and main function.
#pragma data_seg(pop)


int main(int argc, char *argv[])
{
	// Beging by deobfuscating our mutex.
	HANDLE hMutex = CreateMutexA(NULL, TRUE, GetMutexString());

	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		// We are a spawn, run normally
		printf("[+] Normal execution.\n");
		getchar();
		return 0;
	}
	else {
		// We are the first instance
		TCHAR szFilePath[MAX_PATH] = { 0 };
		GetModuleFileName(NULL, szFilePath, MAX_PATH);

		PROCESS_INFORMATION pi = { 0 };
		STARTUPINFO si = { 0 };
		si.cb = sizeof(STARTUPINFO);

		// Create child process
		CreateProcess(szFilePath, NULL, NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, 0, NULL, &si, &pi);
		if (pi.hProcess != NULL) {
			printf("[+] Spawning child process and attaching as a debugger.\n");

			// Debug event
			DEBUG_EVENT de = { 0 };
			while (1)
			{
				WaitForDebugEvent(&de, INFINITE);
				// We only care about when the process terminates
				if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
					break;
				// Otherwise ignore all other events
				ContinueDebugEvent(pi.dwProcessId, pi.dwThreadId, DBG_CONTINUE);
			}
		}

		CloseHandle(pi.hProcess);
		CloseHandle(hMutex);
	}

	return 0;
}

LPSTR GetMutexString()
{
	LPSTR lpMutexStr = calloc(64, 1);
	unsigned char s[] =
	{

		0x98, 0x9b, 0x99, 0x9d, 0xc3, 0x15, 0x6f, 0x6f,
		0x2d, 0xd3, 0xea, 0xae, 0x13, 0xff, 0x7a, 0xbe,
		0x63, 0x36, 0xfc, 0x63, 0xf3, 0x74, 0x32, 0x74,
		0x71, 0x72, 0x4e, 0x2, 0x81, 0x1e, 0x19, 0x20,
		0x44, 0xdf, 0x81, 0xd7, 0x15, 0x92, 0x93, 0x1a,
		0xe7
	};

	for (unsigned int m = 0; m < sizeof(s); ++m)
	{
		unsigned char c = s[m];
		c -= 0xe8;
		c = (c >> 0x5) | (c << 0x3);
		c = -c;
		c += 0x51;
		c = ~c;
		c -= 0x93;
		c = (c >> 0x3) | (c << 0x5);
		c += 0x14;
		c ^= 0x14;
		c = (c >> 0x1) | (c << 0x7);
		c ^= 0xd3;
		c += m;
		c = ~c;
		c = (c >> 0x5) | (c << 0x3);
		c -= 0x2b;
		s[m] = c;
	}
	memcpy(lpMutexStr, s, sizeof(s));
	return lpMutexStr;
}

VOID ThreadMain(LPVOID p)
{
	while (1)
	{
		if (IsDebuggerPresent())
		{
			__asm { int 3; }
		}
		Sleep(500);
	}
	return 0;
}
}