#include "win32memory.hpp"

#include <stdio.h>
#include <psapi.h>
#include <TlHelp32.h>

// Small scanner that compares data locally without page permission checks
// (used internally by the real scan functions)
// ~ gotta go fast ~
inline byte* basicScan(byte* scan_addr, byte* end_addr, char* data, char* mask) {
	for (; scan_addr < end_addr; scan_addr++) {
		char *m = mask, *d = data, *s = reinterpret_cast<char*>(scan_addr);
		for (; *m; m++, d++, s++)
			if (*m == 'x' && *d != *s)
				break;

		if (!*m)
			return scan_addr;
	}

	return 0;
}

// ------------------------
// LOCAL FUNCTIONS
// ------------------------

// Hook local function.
// Takes pointer to target function to be hooked, and the function that should be called in its place.
// Returns pointer to "oldmem" data necessary to unhook function.
void* Memory::Local::placeHook(void* target, void* hook) {
	void* oldmem = malloc(5);
	DWORD oldprot;

	VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldprot);
	memcpy(oldmem, target, 5);

	*reinterpret_cast<byte*>(target) = 0xE9;
	*(reinterpret_cast<uint32_t*>(target) + 1) = reinterpret_cast<uint32_t>(hook) - reinterpret_cast<uint32_t>(target) - 5;

	VirtualProtect(target, 5, oldprot, &oldprot);

	return oldmem;
}

// Unhook a function.
// Takes pointer to hooked function, and pointer to oldmem returned from placeHook() call.
void Memory::Local::revertHook(void* target, void* oldmem) {
	DWORD oldprot;

	VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldprot);
	memcpy(target, oldmem, 5);
	VirtualProtect(target, 5, oldprot, &oldprot);

	free(oldmem);
}

// Scan memory locally.
// scan_addr and end_addr denote the start and end addresses of the scan.
// data points to a buffer containing the data to scan for.
// mask is a c string where each character represents a byte in the data buffer to compare to the scan region.
//   If the character is anything other than an "x" then it is considered to be a wildcard and not compared to the data buffer.
// mem_type is a constant representing the type of memory pages to scan. Can be MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, or MEM_ANY.
// mem_prot is one of microsoft's memory protection constants representing the protection type of pages to scan.
//   There are some custom values for ease of use, such as PAGE_ANYREAD, PAGE_ANYWRITE, and PAGE_ANYEXECUTE.
void* Memory::Local::scan(byte* scan_addr, byte* end_addr, char* data, char* mask, uint32_t mem_type, uint32_t mem_prot) {
	MEMORY_BASIC_INFORMATION mbi;

	while (VirtualQuery(scan_addr, &mbi, sizeof(mbi)) && scan_addr < end_addr) {
		if (mbi.State & MEM_COMMIT && mbi.Type & mem_type && mbi.Protect & mem_prot) {
			size_t scan_size = mbi.RegionSize - (reinterpret_cast<uint32_t>(scan_addr) - reinterpret_cast<uint32_t>(mbi.BaseAddress));
			byte* found = basicScan(scan_addr, scan_addr + scan_size, data, mask);
			if (found)
				return found;
		}
		scan_addr = static_cast<byte*>(mbi.BaseAddress) + mbi.RegionSize;
	}

	return 0;
}

// Finds the end of a function.
// Works by scanning for prolog of next function.
// (it's the fastest way without needing a length disassembler or possibly more complex disassembly tools)
void* Memory::Local::findFuncEnd(void* func) {
	byte* end = (byte*)func + 1;
	while (end[0] != 0x55 || end[1] != 0x8B || end[2] != 0xEC)
		end++;
	return end;
}

// Duplicate a function.
// Copies a function into newly allocated space.
// Returns pointer to copy of function.
void* Memory::Local::duplicateFunc(void* func) {
	size_t func_size = calcFuncSize(func) + 3;
	void* new_func = VirtualAlloc(0, func_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	memcpy(new_func, func, func_size);

	return new_func;
}

// TODO: Possibly add a polymorphic engine (like described in VX heaven archives) somewhere in here??
// It would be so fun... and also make bridges somehow more undetectable

// ------------------------
// REMOTE FUNCTIONS
// ------------------------

// Retrieve the PID of a process from the name of its executable file.
uint32_t Memory::Remote::getPid(const char* exe_name) {
	HANDLE snap_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap_handle == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32 pe32;
	memset(&pe32, 0, sizeof(PROCESSENTRY32));
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(snap_handle, &pe32))
		return 0;

	uint32_t pid = 0;
	do {
		if (!strncmp(pe32.szExeFile, exe_name, strlen(exe_name)))
			pid = pe32.th32ProcessID;
	} while (Process32Next(snap_handle, &pe32));

	CloseHandle(snap_handle);

	return pid;
}

// Retrieve the base address of a module in a remote process by pid.
uint32_t Memory::Remote::getModBase(uint32_t pid, const char* mod_name) {
	HANDLE snap_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snap_handle == INVALID_HANDLE_VALUE)
		return 0;

	MODULEENTRY32 me32;
	memset(&me32, 0, sizeof(MODULEENTRY32));
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(snap_handle, &me32))
		return 0;

	uint32_t base = 0;
	do {
		if (!strncmp(me32.szModule, mod_name, strlen(mod_name)))
			base = reinterpret_cast<uint32_t>(me32.modBaseAddr);
	} while (Module32Next(snap_handle, &me32));

	CloseHandle(snap_handle);

	return base;
}

// Hook function in a remote process.
// Takes handle to the remote process, the (remote) target function to be hooked, and the (remote) function that should be called in its place.
// Returns pointer to "oldmem" data necessary to unhook function.
void* Memory::Remote::placeHook(HANDLE rmt_handle, void* rmt_target, void* rmt_hook) {
	DWORD oldprot;
	unsigned char buffer[5];
	void* oldmem = malloc(5);
	
	VirtualProtectEx(rmt_handle, rmt_target, 5, PAGE_EXECUTE_READWRITE, &oldprot);
	ReadProcessMemory(rmt_handle, rmt_target, oldmem, 5, 0);

	buffer[0] = 0xE9;
	*(reinterpret_cast<uint32_t*>(buffer + 1)) = reinterpret_cast<uint32_t>(rmt_hook) - reinterpret_cast<uint32_t>(rmt_target) - 5;
	WriteProcessMemory(rmt_handle, rmt_target, buffer, 5, 0);

	VirtualProtectEx(rmt_handle, rmt_target, 5, oldprot, &oldprot);

	return oldmem;
}

// Unhook a function.
// Takes handle to the remote process, pointer to (remote) hooked function, and pointer to oldmem returned from placeHook() call.
void Memory::Remote::revertHook(HANDLE rmt_handle, void* rmt_target, void* oldmem) {
	DWORD oldprot;

	VirtualProtectEx(rmt_handle, rmt_target, 5, PAGE_EXECUTE_READWRITE, &oldprot);
	WriteProcessMemory(rmt_handle, rmt_target, oldmem, 5, 0);
	VirtualProtectEx(rmt_handle, rmt_target, 5, oldprot, &oldprot);

	free(oldmem);
}

// Allocate remote space for and write bytes to remote process (and provide memory protection constant to allocate the space with)
void* Memory::Remote::allocWrite(HANDLE rmt_handle, void* local_src, size_t len, DWORD protect) {
	void* rmt_dst = VirtualAllocEx(rmt_handle, 0, len, MEM_COMMIT | MEM_RESERVE, protect); // TODO: split this function into one that uses heapalloc and one that uses virtualalloc)
	if (!rmt_dst)
		return 0;

	if (!WriteProcessMemory(rmt_handle, rmt_dst, local_src, len, 0)) {
		VirtualFreeEx(rmt_handle, rmt_dst, 0, MEM_RELEASE);
		return 0;
	}

	return rmt_dst;
}

// Allocate local space for and read bytes from remote process (and provide memory protection constant to allocate the space with)
void* Memory::Remote::allocRead(HANDLE rmt_handle, void* rmt_src, size_t len, DWORD protect) {
	void* local_dst = VirtualAlloc(0, len, MEM_COMMIT | MEM_RESERVE, protect);
	if (!local_dst)
		return 0;

	if (!ReadProcessMemory(rmt_handle, rmt_src, local_dst, len, 0)) {
		VirtualFree(local_dst, 0, MEM_RELEASE);
		return 0;
	}

	return local_dst;
}

// Allocate local space for and read string from remote process.
// Works by scanning for null terminator of remote string.
// Function primarily for ease of use.
char* Memory::Remote::allocReadString(HANDLE rmt_handle, void* rmt_src) {
	void* null_addr = scan(rmt_handle, rmt_src, reinterpret_cast<void*>(UINT_MAX), const_cast<char*>("\x00"), const_cast<char*>("x"), MEM_ANY, PAGE_ANYREAD);
	size_t str_size = reinterpret_cast<uint32_t>(null_addr) - reinterpret_cast<uint32_t>(rmt_src);
	return reinterpret_cast<char*>(allocRead(rmt_handle, rmt_src, str_size, PAGE_READWRITE));
}

// Scan memory of a remote process.
// rmt_scan_addr and rmt_end_addr denote the start and end (remote) addresses of the scan.
// data points to a (local) buffer containing the data to scan for.
// mask is a (local) c string where each character represents a byte in the data buffer to compare to the scan region.
//   If the character is anything other than an "x" then it is considered to be a wildcard and not compared to the data buffer.
// mem_type is a constant representing the type of memory pages to scan. Can be MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, or MEM_ANY.
// mem_prot is one of microsoft's memory protection constants representing the protection type of pages to scan.
//   There are some custom values for ease of use, such as PAGE_ANYREAD, PAGE_ANYWRITE, and PAGE_ANYEXECUTE.
void* Memory::Remote::scan(HANDLE rmt_handle, byte* rmt_scan_addr, byte* rmt_end_addr, char* data, char* mask, uint32_t mem_type, uint32_t mem_prot) {
	MEMORY_BASIC_INFORMATION mbi;

	while (VirtualQueryEx(rmt_handle, rmt_scan_addr, &mbi, sizeof(mbi)) && rmt_scan_addr < rmt_end_addr) {
		if (mbi.State & MEM_COMMIT && mbi.Type & mem_type && mbi.Protect & mem_prot) {
			size_t scan_size = mbi.RegionSize - (reinterpret_cast<uint32_t>(rmt_scan_addr) - reinterpret_cast<uint32_t>(mbi.BaseAddress));
			byte* local_scan_start = static_cast<byte*>(allocReadData(rmt_handle, rmt_scan_addr, scan_size));
			if (local_scan_start) {
				byte* found = basicScan(local_scan_start, local_scan_start + scan_size, data, mask);
				if (found)
					return found - local_scan_start + rmt_scan_addr;
			}
			VirtualFree(local_scan_start, 0, MEM_RELEASE);
		}
		rmt_scan_addr = static_cast<byte*>(mbi.BaseAddress) + mbi.RegionSize;
	}

	return 0;
}

// Create a duplicate of a remote function within the remote process.
// Does not patch calls/jmps/etc.
void* Memory::Remote::duplicateFunc(HANDLE rmt_handle, void* rmt_func) {
	size_t func_size = calcFuncSize(rmt_handle, rmt_func) + 3;
	void* local_func = allocReadCode(rmt_handle, rmt_func, func_size);
	void* new_rmt_func = allocWriteCode(rmt_handle, local_func, func_size);

	VirtualFree(local_func, 0, MEM_RELEASE);
	return new_rmt_func;
}