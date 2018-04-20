#include <Windows.h>
#include <TlHelp32.h>
#include <Winternl.h>
#include <stdio.h>
#include <Psapi.h>

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
	PFNNtUnmapViewOfSection NtUnmapViewOfSection;
	PFNtCreateSection NtCreateSection;
	PFNtMapViewOfSection NtMapViewOfSection;

	const auto WoWProcessName = L"wowb.exe";
	HANDLE threadHandles[1000];
}
/*
---------------------------
WowB-64
---------------------------
This application has encountered a critical error:

ERROR #123 (0x8510007b) This memory block has been corrupted by an out-of-bounds memory write.


Program:	D:\World of Warcraft Beta\WowB-64.exe
ProcessID:	46220
File:	..\..\..\Storm\Source\SMemMalloc.cpp
Line:	1361

Memory corrupted

Press OK to terminate the application.
---------------------------
OK
---------------------------
*/

void memzero(void* buf, size_t size)
{
	for (int i = 0; i < size; ++i)
	{
		((char*)buf)[i] = 0;
	}
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

size_t AllocSharedSection(DWORD pid, size_t regionSize)
{
	auto handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid);

	HANDLE hSection; LARGE_INTEGER li; li.LowPart = regionSize; li.HighPart = 0; size_t numRead;
	NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &li, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	PVOID sectionBaseAddress = 0; size_t viewSize = 0;
	NtMapViewOfSection(hSection, handle, &sectionBaseAddress, NULL, NULL, NULL, &viewSize, 1, NULL, PAGE_EXECUTE_READWRITE);
	NtMapViewOfSection(hSection, GetCurrentProcess(), &sectionBaseAddress, NULL, NULL, NULL, &viewSize, 1, NULL, PAGE_EXECUTE_READWRITE);
	
	CloseHandle(handle);
	return (size_t)sectionBaseAddress;
}


int parseHex(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}


size_t Match(const char* mem, const size_t len, const char* sighex)
{
	const char* origSig = sighex;
	size_t siglen = strlen(sighex) / 2;
	char* sig = new char[siglen];
	bool* match = new bool[siglen];

	for (size_t i = 0; i < siglen; ++i) {
		int high = parseHex(sighex[0]);
		int low = parseHex(sighex[1]);
		if (high >= 0 && low >= 0) {
			sig[i] = (unsigned char)(high * 16 + low);
			match[i] = true;
		} else {
			match[i] = false;
		}
		sighex += 2;
	}
	size_t current = 0;
	while (current + siglen < len) {
		for (int i = 0; i < siglen; ++i) {
			if (mem[current + i] != sig[i] && match[i]) {
				current++;
				goto nomatch;
			}
		}
		return current;
	nomatch:
		;
	}
	printf("Cannot find %s\n", origSig);
	return 0;
	delete sig;
	delete match;
	
}


typedef int(__fastcall* LoadToc)(const char* contexts, const char* addonName, const size_t secure);
typedef HANDLE (WINAPI *pGetProcessHeap)(VOID);
typedef LPVOID (WINAPI* pHeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);

#pragma pack(push, 1)
struct InjContext {
	int done;
	size_t whatever;
	LoadToc loadToc;
	pGetProcessHeap getProcessHeap;
	pHeapAlloc heapAlloc;
	
	char Buffer2[4096];
	char Buffer[200000];

	char* tocContexts[100];
	int addons;
	char* addonNames[100];
	int* Addr1;
	size_t* Addr2;

	char nopslip[100];
	__int16 _0xb948;
	size_t addr;
	char code[2000];
};
#pragma pack(pop)

void LoadAddons(InjContext* ctx,wchar_t* ExePath)
{
	ctx->addons = 0;
	char* Buf = ctx->Buffer2;
	char* TocBuf = ctx->Buffer;
	ctx->addonNames[0] = Buf;

	int j = -1;
	for (int i = 0; i < wcslen(ExePath); ++i) {
		if (ExePath[i] == L'\\')
			j = i;
	}
	if (j != -1) ExePath[j] = 0;
	wchar_t InterfaceAddonPath[260];
	WIN32_FIND_DATA fData; memset(&fData, 0, sizeof(WIN32_FIND_DATA));
	swprintf(InterfaceAddonPath, L"%s\\Interface\\Addons\\*", ExePath);


	HANDLE hFind = FindFirstFile(InterfaceAddonPath, &fData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (fData.cFileName[0] == L'.') continue;
			wcscpy(InterfaceAddonPath, fData.cFileName);
			j = -1;
			for (int i = 0; i < wcslen(InterfaceAddonPath); ++i) {
				if (InterfaceAddonPath[i] == L'\\')
					j = i;
			}
			if (j != -1) InterfaceAddonPath[j] = 0;
			auto AddonName = &InterfaceAddonPath[j + 1];

			wchar_t TocPath[260];
			swprintf(TocPath, L"%s\\Interface\\Addons\\%s\\%s.toc", ExePath, AddonName, AddonName);
			if (GetFileAttributes(TocPath) != INVALID_FILE_ATTRIBUTES)
			{
				ctx->addons++;
				ctx->addonNames[ctx->addons] = Buf;
				wcstombs(Buf, AddonName, 1000);
				Buf += strlen(Buf);
				*Buf++ = 0;

				ctx->tocContexts[ctx->addons] = TocBuf;
				FILE* fp = _wfopen(TocPath, L"rb");
				while (!feof(fp)) {
					fread(TocBuf++, 1, 1, fp);
				}
				fclose(fp);
				*TocBuf++ = 0;
			}


		} while (FindNextFile(hFind, &fData));
		FindClose(hFind);
	}
}

void __fastcall InjectionCode(InjContext* ctx) {
	// Why no x64 inline assembly, making things so complicated
	char* mem = (char*)ctx->heapAlloc(ctx->getProcessHeap(), 0, 4096);
	for (int i = 0; i < 4096; ++i)
		mem[i] = ctx->Buffer2[i];
	for (int i = 1; i <= ctx->addons; ++i) {
		char* name = ctx->addonNames[i] - ctx->Buffer2 + mem;
		ctx->loadToc(ctx->tocContexts[i], name, 100);
	}
	// Not really needed
	//*ctx->Addr1 = ctx->addons;
	//*ctx->Addr2 = (size_t)&ctx->addonNames;
	// spin
	while (true)
		ctx->done = 1;
}

void GetSharedPageLocation(HANDLE handle, size_t* sharedPageLoc, size_t* sharedPageOffset)
{
	SYSTEM_INFO sysinfo; memset(&sysinfo, 0, sizeof(sysinfo));
	GetSystemInfo(&sysinfo);
	*sharedPageOffset = 0;
	LPVOID addr = sysinfo.lpMinimumApplicationAddress;
	while (addr < sysinfo.lpMaximumApplicationAddress) {
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQueryEx(handle, addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION)) {
			addr = (LPVOID)((size_t)addr + mbi.RegionSize);
			if (mbi.Type == MEM_MAPPED && mbi.RegionSize == 0x1000 && mbi.AllocationProtect == PAGE_READWRITE) {
				PSAPI_WORKING_SET_EX_INFORMATION info = { 0 };
				info.VirtualAddress = mbi.BaseAddress;
				QueryWorkingSetEx(handle, &info, sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
				if (info.VirtualAttributes.ShareCount == 2) {
					*sharedPageLoc = (size_t)mbi.BaseAddress;
				}
			}
			if (mbi.Type == MEM_MAPPED && mbi.AllocationProtect == PAGE_EXECUTE_READ) {
				PSAPI_WORKING_SET_EX_INFORMATION info = { 0 };
				size_t currentAddr = (size_t)mbi.BaseAddress;
				while (currentAddr < (size_t)mbi.AllocationBase + mbi.RegionSize) {
					info.VirtualAddress = (PVOID)currentAddr;
					QueryWorkingSetEx(handle, &info, sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
					if (info.VirtualAttributes.ShareCount > 1) {
						*sharedPageOffset = (size_t)(currentAddr - (size_t)mbi.BaseAddress);
					}
					currentAddr += sysinfo.dwPageSize;
				}

			}
		}
		else {
			addr = (LPVOID)((size_t)addr + sysinfo.dwPageSize);
		}
	}
}

void ReMapWoWMemory(DWORD pid, void** address, int* length, size_t modBaseAddr) {
	NTSTATUS status;
	{
		*address = (void*)modBaseAddr;
		auto handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid);
		if (handle == INVALID_HANDLE_VALUE) return;
		MEMORY_BASIC_INFORMATION mbi;
		VirtualQueryEx(handle, (LPVOID)(((size_t)modBaseAddr)), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		size_t regionSize = mbi.RegionSize + ((size_t)mbi.BaseAddress - (size_t)mbi.AllocationBase);
		HANDLE hSection; LARGE_INTEGER li; li.LowPart = regionSize; li.HighPart = 0;
#define SEC_NO_CHANGE      0x400000
		size_t numRead;
		// Query the shared page
		size_t sharedPageLoc; size_t sharedPageOffset;
		GetSharedPageLocation(handle, &sharedPageLoc, &sharedPageOffset);
		// Create a new memory section
		status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &li, PAGE_EXECUTE_READWRITE, SEC_COMMIT | SEC_NO_CHANGE, NULL);
		PVOID sectionBaseAddress = mbi.AllocationBase; size_t viewSize = 0;
		// Map this section to our own address space
		status = NtMapViewOfSection(hSection, GetCurrentProcess(), &sectionBaseAddress, NULL, NULL, NULL, &viewSize, 1, NULL, PAGE_EXECUTE_READWRITE);
		// Copy WoW Memory back to this section
		ReadProcessMemory(handle, mbi.AllocationBase, sectionBaseAddress, regionSize, &numRead);
		// Unmap view of section in WoW
		status = NtUnmapViewOfSection(handle, mbi.AllocationBase);
		// Map our new view of section
		status = NtMapViewOfSection(hSection, handle, &mbi.AllocationBase, NULL, NULL, NULL, &viewSize, 1, NULL, PAGE_EXECUTE_READ);
		if (sharedPageLoc) {
			// Unmap the shared page
			status = NtUnmapViewOfSection(handle, (PVOID)sharedPageLoc);
			// Map the Shared page
			li.LowPart = sharedPageOffset; li.HighPart = 0; viewSize = 0x1000;
			status = NtMapViewOfSection(hSection, handle, (PVOID*)&sharedPageLoc, NULL, NULL, &li, &viewSize, 1, NULL, PAGE_READWRITE);
		}
		*length = regionSize;
		return;
	}
}

size_t GetWoWAddrAndExe(DWORD pid, wchar_t* ExePath) {
	

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 me; memzero(&me, sizeof(me)); me.dwSize = sizeof(me);
	for (Module32First(hSnapshot, &me); me.th32ModuleID; Module32Next(hSnapshot, &me)) {
		if (lstrcmpi(me.szModule, WoWProcessName) == 0) {
			CloseHandle(hSnapshot);
			wcscpy(ExePath, me.szExePath);
			return (size_t)me.modBaseAddr;
		}
	}
	CloseHandle(hSnapshot);
	return 0;


}

void Inject(HANDLE victim, InjContext* ctx) {



	CONTEXT context; CONTEXT context2;
	context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(victim, &context);
	memcpy(&context2, &context, sizeof(CONTEXT));



	context2.Rip = (size_t)&ctx->nopslip;
	SetThreadContext(victim, &context2);
	// Run our code
	ResumeThread(victim);
	// wait until
	while (ctx->done == 0); //spin

	SuspendThread(victim);
	SetThreadContext(victim, &context);

	
}


bool PatchAddons(int pid)
{
	int nHandles = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
	THREADENTRY32 te; te.dwSize = sizeof(te);
	HANDLE victim = 0;

	for (Thread32First(hSnapshot, &te); ; ) {
		if (te.th32OwnerProcessID == pid) {
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, te.th32ThreadID);
			if (SuspendThread(hThread) == 0 && !victim)
				victim = hThread;
			threadHandles[nHandles++] = hThread;
		}
		if (!Thread32Next(hSnapshot, &te)) break;

	}
	CloseHandle(hSnapshot);

	typedef char*(__fastcall* GetAddonStructByName)(size_t addonBase, size_t addonName);
	typedef char*(__fastcall* GetAddonNameById)(size_t id);

	//const char* sig = "48895C240848896C2410488974241848897C24204154415641574883EC408379";
	const char* sig2 = "4883EC288B05????????3BC8720733C04883C428C38BD1483BD07310488B05??";
	const char* loadTocSig = "48895C241855565741564157488DAC24B0FBFFFF4881EC5005000048898D8004";
	const char* callCASFree = "498BCFE8??????FEE8??????0041387E4D0F84AC00000083F8010F86A3000000";

	char* mem; int len; wchar_t ExePath[260];
	ReMapWoWMemory(pid, (void**)&mem, &len, GetWoWAddrAndExe(pid, ExePath));
	
	//GetAddonStructByName getAddonByName = (GetAddonStructByName)(Match(mem,len,sig)+mem);
	GetAddonNameById getAddonById = (GetAddonNameById)(Match(mem, len, sig2) + mem);
	LoadToc loadToc = (LoadToc)(Match(mem, len, loadTocSig) + mem);
	void* callCASFreeAddr = (void*)(Match(mem, len, callCASFree) + mem + 3);
	
	
	//getAddonByName((size_t)addonBase, (size_t)"Blizzard_WowTokenUI");
#pragma pack(push, 1)
	struct mov_instruction {
		char _opcode; // 0x8b05
		char _target_register;
		__int32 offset;
	};
#pragma pack(pop)
	auto mov1 = (mov_instruction*)((size_t)getAddonById + 4);
	int* Addr1 = (int*)((size_t)mov1 + mov1->offset + 6);

	auto mov2 = (mov_instruction*)((size_t)getAddonById + 29);
	char** Addr2 = (char**)((size_t)mov2 + mov2->offset + 6);

	size_t addr = AllocSharedSection(pid, sizeof(InjContext));
	InjContext* ctx = (InjContext*)addr;
	memcpy(&ctx->code, InjectionCode, 2000);
	memset(&ctx->nopslip, 0x90, 100);
	//ctx->nopslip[50] = 0xcc;
	ctx->_0xb948 = 0xb948; //mov ecx
	ctx->addr = addr;
	ctx->done = 0;
	ctx->Addr1 = Addr1;
	ctx->Addr2 = (size_t*)Addr2;
	ctx->loadToc = loadToc;
	ctx->getProcessHeap = GetProcessHeap;
	ctx->heapAlloc = HeapAlloc;
	LoadAddons(ctx, ExePath);

	// Patch CASFree, we don't want WoW to free our mem
	char orig[5];
	char patch[] = { 0x90,0x90,0x90,0x90,0x90 };
	memcpy(orig, callCASFreeAddr, 5);
	memcpy(callCASFreeAddr, patch, 5);

	Inject(victim, ctx);
	memcpy(callCASFreeAddr, orig, 5);

	auto handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid);
	NtUnmapViewOfSection(handle, (PVOID)addr);
	CloseHandle(handle);

	for (int i = 0; i< nHandles; ++i)
	{
		ResumeThread(threadHandles[i]);
		CloseHandle(threadHandles[i]);
	}


	return true;
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
	HMODULE hModule = GetModuleHandle(L"ntdll.dll");
	NtUnmapViewOfSection = (PFNNtUnmapViewOfSection)GetProcAddress(hModule, "NtUnmapViewOfSection");
	NtCreateSection = (PFNtCreateSection)GetProcAddress(hModule, "NtCreateSection");
	NtMapViewOfSection = (PFNtMapViewOfSection)GetProcAddress(hModule, "NtMapViewOfSection");

	auto pid = GetWoWPID();
	if (pid) {
		PatchAddons(pid);
		printf("\n");
	} else {
		printf("process not found\n");
	}
	//system("pause");
	ExitProcess(0);
    return 0;
}

