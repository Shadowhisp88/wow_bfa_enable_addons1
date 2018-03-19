#include <Windows.h>
#include <TlHelp32.h>
#include <Winternl.h>


typedef NTSTATUS(WINAPI *PFNNtUnmapViewOfSection)(IN HANDLE ProcessHandle, IN PVOID BaseAddress);
typedef NTSTATUS(WINAPI *PFNtCreateSection)(
	__out PHANDLE SectionHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PLARGE_INTEGER MaximumSize,
	__in ULONG SectionPageProtection,
	__in ULONG AllocationAttributes,
	__in_opt HANDLE FileHandle
	);
typedef NTSTATUS(WINAPI *PFNtMapViewOfSection)(
	__in HANDLE SectionHandle,
	__in HANDLE ProcessHandle,
	__inout PVOID *BaseAddress,
	__in ULONG_PTR ZeroBits,
	__in SIZE_T CommitSize,
	__inout_opt PLARGE_INTEGER SectionOffset,
	__inout PSIZE_T ViewSize,
	__in ULONG InheritDisposition,
	__in ULONG AllocationType,
	__in ULONG Win32Protect
	);

namespace {
	// Declear here to avoid _chkstk calls
	HANDLE threadHandles[1000]; int nHandles = 0;
	const int page_size = 4096;
	char buf[page_size];
	const auto WoWProcessName = L"wowb-64.exe";
}

void memzero(void* buf, size_t size)
{
	for (int i = 0; i < size; ++i)
	{
		((char*)buf)[i] = 0;
	}
}

int __cdecl memcmp(char const* _Buf1, char const* _Buf2, size_t size)
{
	for (int i = 0; i < size; ++i) {
		if (_Buf1[i] != _Buf2[i])
			return 1;
	}
	return 0;
}

DWORD GetWoWPID()
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe; memzero(&pe, sizeof(pe)); pe.dwSize = sizeof(pe);
	for (Process32First(hSnapshot, &pe); Process32Next(hSnapshot, &pe);) {
		if (lstrcmpi(pe.szExeFile, WoWProcessName) == 0) {
			CloseHandle(hSnapshot);
			return pe.th32ProcessID;
		}
	}
	CloseHandle(hSnapshot);
	return 0;
}

bool FindWoWMemoryRegion(DWORD pid, void** address, int* length)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 me; memzero(&me, sizeof(me)); me.dwSize = sizeof(me);
	for (Module32First(hSnapshot, &me); me.th32ModuleID ; Module32Next(hSnapshot, &me)) {
		if (lstrcmpi(me.szModule, WoWProcessName) == 0) {
			CloseHandle(hSnapshot);
			*address = (void*)me.modBaseAddr;
			*length = me.modBaseSize;
			return true;
		}
	}
	CloseHandle(hSnapshot);
	return false;
}


bool ScanAndPatch(DWORD pid, void* address, int length) {
	int current = 0; 
	const char sig[] = {0x75, 0x19, 0x4C, 0x8B, 0x6C, 0x24, 0x78, 0x32, 0xC0, 0x41, 0xC7, 0x06, 0x05, 0x00, 0x00, 0x00 };
	size_t len = sizeof(sig);

	auto handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid);
	if (handle == INVALID_HANDLE_VALUE) return false;

	size_t addr = 0;
	int p = 0;
	while (current + page_size < length) {
		size_t numRead;
		ReadProcessMemory(handle, (LPVOID)(((size_t)address) + current), &buf, page_size, &numRead);
		if (numRead > 0) {
			if (p != 0) {
				if (memcmp(buf, sig + p, len - p) == 0) {
					addr = current - page_size;
					p = page_size - p;
					break;
				}
				p = 0;
			}
			for (int i = 0; i < page_size; ++i) {
				if (i + len < page_size) {
					if (memcmp(buf + i, sig, len) == 0) {
						addr = current;
						p = i;
						break;
					}
				}
				else {
					if (memcmp(buf + i, sig, page_size - i) == 0) {
						p = page_size - i;
						break;
					}
				}
			}
			if (addr) break;
		}
		current += page_size;
	}
	if (addr) {
		size_t numRead;

		MEMORY_BASIC_INFORMATION mbi;
		VirtualQueryEx(handle, (LPVOID)(((size_t)address) + addr), &mbi, sizeof(MEMORY_BASIC_INFORMATION));

		// Suspend WoW process
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
		THREADENTRY32 te; te.dwSize = sizeof(te);
		
		
		for (Thread32First(hSnapshot, &te); ; ) {
			if (te.th32OwnerProcessID == pid) {
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, te.th32ThreadID);
				SuspendThread(hThread);
				threadHandles[nHandles++] = hThread;
			}
			if (!Thread32Next(hSnapshot, &te)) break;

		}
		CloseHandle(hSnapshot);

		CreateRemoteThread(handle, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "ExitThread"), 0, 0, 0);

		HMODULE hModule = GetModuleHandle(L"ntdll.dll");
		PFNNtUnmapViewOfSection NtUnmapViewOfSection = (PFNNtUnmapViewOfSection)GetProcAddress(hModule, "NtUnmapViewOfSection");
		PFNtCreateSection NtCreateSection = (PFNtCreateSection)GetProcAddress(hModule, "NtCreateSection");
		PFNtMapViewOfSection NtMapViewOfSection = (PFNtMapViewOfSection)GetProcAddress(hModule, "NtMapViewOfSection");
		NTSTATUS status;

		size_t regionSize = mbi.RegionSize + ((size_t)mbi.BaseAddress - (size_t)mbi.AllocationBase);
		HANDLE hSection; LARGE_INTEGER li; li.LowPart = regionSize; li.HighPart = 0;
#define SEC_NO_CHANGE      0x400000
		// Create a new memory section
		status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &li, PAGE_EXECUTE_READWRITE, SEC_COMMIT | SEC_NO_CHANGE, NULL);
		PVOID sectionBaseAddress = NULL; size_t viewSize = 0; 
		// Map this section to our own address space
		status = NtMapViewOfSection(hSection, GetCurrentProcess(), &sectionBaseAddress, NULL, NULL, NULL, &viewSize, 1, NULL, PAGE_EXECUTE_READWRITE);
		// Copy WoW Memory back to this section
		ReadProcessMemory(handle, mbi.AllocationBase, sectionBaseAddress, regionSize, &numRead);
		// Unmap view of section in WoW
		status = NtUnmapViewOfSection(handle, mbi.AllocationBase);
		// Map our new view of section
		status = NtMapViewOfSection(hSection, handle, &mbi.AllocationBase, NULL, NULL, NULL, &viewSize, 1, NULL, PAGE_EXECUTE_READ);

		for (int i = 0; i< nHandles; ++i)
		{
			ResumeThread(threadHandles[i]);
			CloseHandle(threadHandles[i]);
		}
		CloseHandle(handle);

		system("pause");
		// Patch
		char orig = ((char*)sectionBaseAddress)[addr + p];
		((char*)sectionBaseAddress)[addr + p] = 0xEB;
		system("pause");
		((char*)sectionBaseAddress)[addr + p] = orig;
		// Unmap view of section in current process
		status = NtUnmapViewOfSection(GetCurrentProcess(), sectionBaseAddress);
						
		const auto* message = L"Done patching\n";
		WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), message, lstrlen(message), 0, 0);
		return true;
	}
	const auto* message = L"pattern not found\n";
	WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), message, lstrlen(message), 0, 0);
	CloseHandle(handle);
	return false;
}

void GetSEDebugPriv()
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tokenPriv;
	LUID luidDebug;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) != FALSE)
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug) != FALSE)
		{
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luidDebug;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, 0, NULL, NULL);
		}
	}
	CloseHandle(hToken);
}

int main()
{
	GetSEDebugPriv();

	auto pid = GetWoWPID();
	//printf("pid = %d\n", pid);
	if (pid) {
		void* addr; int len;
		FindWoWMemoryRegion(pid, &addr, &len);
		ScanAndPatch(pid, addr, len);
	} else {
		const auto* message = L"process not found\n";
		WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), message, lstrlen(message), 0, 0);
	}
	ExitProcess(0);
    return 0;
}

