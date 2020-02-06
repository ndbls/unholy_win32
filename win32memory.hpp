#pragma once
#include <stdint.h>
#include <Windows.h>

// Various constant shorthands
#define PAGE_ANYREAD     (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)
#define PAGE_ANYWRITE    (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)
#define PAGE_ANYEXECUTE  (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)
#define MEM_ANY          (MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE)

namespace Memory {
	namespace Local {
		// Free all of the given pointers with VirtualFree.
		template <typename T>
		void freeAll(T mem) {
			VirtualFree(reinterpret_cast<void*>(mem), 0, MEM_RELEASE);
		}

		// Free all of the given pointers with VirtualFree.
		template <typename T, typename... Args>
		void freeAll(T first, Args... args) {
			freeAll(first);
			freeAll(args...);
		}

		// Hook local function.
		void* placeHook(void* target, void* hook);

		// Hook local function.
		template <typename T1, typename T2>
		inline void* placeHook(T1 target, T2 hook) {
			return placeHook(reinterpret_cast<void*>(target), reinterpret_cast<void*>(hook));
		}

		// Unhook a function.
		void revertHook(void* target, void* oldmem);

		// Unhook a function.
		template <typename T>
		inline void revertHook(T target, void* oldmem) {
			revertHook(reinterpret_cast<void*>(target), oldmem);
		}

		// Scan memory locally.
		void* scan(byte* start_addr, byte* end_addr, char* data, char* mask, uint32_t mem_type, uint32_t mem_prot);

		// Scan memory locally.
		inline void* scan(void* start_addr, void* end_addr, char* data, char* mask, uint32_t mem_type, uint32_t mem_prot) {
			return scan(static_cast<byte*>(start_addr), static_cast<byte*>(end_addr), data, mask, mem_type, mem_prot);
		}

		// Scan memory locally.
		inline void* scan(uint32_t start_addr, uint32_t end_addr, char* data, char* mask, uint32_t mem_type, uint32_t mem_prot) {
			return scan(reinterpret_cast<byte*>(start_addr), reinterpret_cast<byte*>(end_addr), data, mask, mem_type, mem_prot);
		}

		// Finds the end of a function.
		// Works by scanning for prolog of next function.
		void* findFuncEnd(void* func);

		// Determines the size of a function in bytes.
		// Works by scanning for prolog of next function.
		inline size_t calcFuncSize(void* func) {
			return reinterpret_cast<size_t>(findFuncEnd(func)) - reinterpret_cast<size_t>(func);
		}

		// Duplicate a function.
		// Does not patch calls/jmps/etc.
		void* duplicateFunc(void* func);

		// Duplicate a function.
		// Does not patch calls/jmps/etc.
		template <typename T>
		inline T duplicateFunc(void* func) {
			return reinterpret_cast<T>(duplicateFunc(func));
		}
	}

	namespace Remote {
		// Retrieve the PID of a process from the name of its executable file.
		uint32_t getPid(const char* exe_name);

		// Retrieve the base address of a module in a remote process by pid.
		uint32_t getModBase(uint32_t pid, const char* mod_name);

		// Free all of the given (remote) pointers with VirtualFreeEx.
		template <typename T>
		void freeAll(HANDLE rmt_handle, T mem) {
			VirtualFreeEx(rmt_handle, reinterpret_cast<void*>(mem), 0, MEM_RELEASE);
		}

		// Free all of the given (remote) pointers with VirtualFreeEx.
		template <typename T, typename... Args>
		void freeAll(HANDLE rmt_handle, T first, Args... args) {
			freeAll(rmt_handle, first);
			freeAll(rmt_handle, args...);
		}

		// Hook function in a remote process.
		void* placeHook(HANDLE rmt_handle, void* rmt_target, void* rmt_hook);

		// Hook function in a remote process.
		template <typename T1, typename T2>
		inline void* placeHook(HANDLE rmt_handle, T1 rmt_target, T2 rmt_hook) {
			return placeHook(rmt_handle, reinterpret_cast<void*>(rmt_target), reinterpret_cast<void*>(rmt_hook));
		}

		// Unhook a function.
		void revertHook(HANDLE rmt_handle, void* rmt_target, void* oldmem);

		// Unhook a function.
		template <typename T>
		inline void revertHook(HANDLE rmt_handle, T rmt_target, void* oldmem) {
			revertHook(rmt_handle, reinterpret_cast<void*>(rmt_target), oldmem);
		}

		// Allocate remote space for and write bytes to remote process.
		// (and provide memory protection constant to allocate the space with)
		void* allocWrite(HANDLE rmt_handle, void* local_src, size_t len, DWORD protect);

		// Allocate remote space for and write bytes to remote process.
		// (and provide memory protection constant to allocate the space with)
		template <typename T>
		inline T allocWrite(HANDLE rmt_handle, void* local_src, size_t len, DWORD protect) {
			return reinterpret_cast<T>(allocWrite(rmt_handle, local_src, len, protect));
		}

		// Shorthand for allocWrite with protect = PAGE_READWRITE.
		inline void* allocWriteData(HANDLE rmt_handle, void* local_src, size_t len) {
			return reinterpret_cast<void*>(allocWrite(rmt_handle, local_src, len, PAGE_READWRITE));
		}

		// Shorthand for allocWrite with protect = PAGE_READWRITE.
		template <typename T>
		inline T allocWriteData(HANDLE rmt_handle, void* local_src, size_t len) {
			return reinterpret_cast<T>(allocWrite(rmt_handle, local_src, len, PAGE_READWRITE));
		}

		// Shorthand for allocWrite with protect = PAGE_EXECUTE_READWRITE.
		inline void* allocWriteCode(HANDLE rmt_handle, void* local_src, size_t len) {
			return reinterpret_cast<void*>(allocWrite(rmt_handle, local_src, len, PAGE_EXECUTE_READWRITE));
		}

		// Shorthand for allocWrite with protect = PAGE_EXECUTE_READWRITE.
		template <typename T>
		inline T allocWriteCode(HANDLE rmt_handle, void* local_src, size_t len) {
			return reinterpret_cast<T>(allocWrite(rmt_handle, local_src, len, PAGE_EXECUTE_READWRITE));
		}

		// Allocate remote space for and write local string to remote process.
		inline void* allocWriteString(HANDLE rmt_handle, void* local_src) {
			return allocWrite(rmt_handle, local_src, strlen(reinterpret_cast<char*>(local_src)), PAGE_READWRITE);
		}

		// Allocate remote space for and write local string to remote process.
		inline char* allocWriteString(HANDLE rmt_handle, char* local_src) {
			return reinterpret_cast<char*>(allocWrite(rmt_handle, local_src, strlen(reinterpret_cast<char*>(local_src)), PAGE_READWRITE));
		}

		// Allocate remote space for and write local string to remote process.
		inline char* allocWriteString(HANDLE rmt_handle, const char* local_src) {
			return reinterpret_cast<char*>(allocWrite(rmt_handle, const_cast<char*>(local_src), strlen(const_cast<char*>(local_src)), PAGE_READWRITE));
		}

		// Allocate local space for and read bytes from remote process.
		// (and provide memory protection constant to allocate the space with)
		void* allocRead(HANDLE rmt_handle, void* rmt_src, size_t len, DWORD protect);

		// Allocate local space for and read bytes from remote process.
		// (and provide memory protection constant to allocate the space with)
		template <typename T>
		inline T allocRead(HANDLE rmt_handle, void* rmt_src, size_t len, DWORD protect) {
			return reinterpret_cast<T>(allocRead(rmt_handle, rmt_src, len, protect));
		}

		// Shorthand for allocRead with protect = PAGE_READWRITE.
		inline void* allocReadData(HANDLE rmt_handle, void* rmt_src, size_t len) {
			return reinterpret_cast<void*>(allocRead(rmt_handle, rmt_src, len, PAGE_READWRITE));
		}

		// Shorthand for allocRead with protect = PAGE_READWRITE
		template <typename T>
		inline T allocReadData(HANDLE rmt_handle, void* rmt_src, size_t len) {
			return reinterpret_cast<T>(allocRead(rmt_handle, rmt_src, len, PAGE_READWRITE));
		}

		// Shorthand for allocRead with protect = PAGE_EXECUTE_READWRITE.
		inline void* allocReadCode(HANDLE rmt_handle, void* rmt_src, size_t len) {
			return reinterpret_cast<void*>(allocRead(rmt_handle, rmt_src, len, PAGE_EXECUTE_READWRITE));
		}

		// Shorthand for allocRead with protect = PAGE_EXECUTE_READWRITE.
		template <typename T>
		inline T allocReadCode(HANDLE rmt_handle, void* rmt_src, size_t len) {
			return reinterpret_cast<T>(allocRead(rmt_handle, rmt_src, len, PAGE_EXECUTE_READWRITE));
		}

		// Allocate local space for and read string from remote process.
		char* allocReadString(HANDLE rmt_handle, void* rmt_src);

		// TODO: make more organized templates for the scanners jeeesus
		// (can't believe I'm const casting data and mask args 90% of the time I use the scanners...)

		// Scan memory of a remote process.
		void* scan(HANDLE rmt_handle, byte* rmt_start_addr, byte* rmt_end_addr, char* data, char* mask, uint32_t mem_type, uint32_t mem_prot);

		// Scan memory of a remote process.
		inline void* scan(HANDLE rmt_handle, void* rmt_start_addr, void* rmt_end_addr, char* data, char* mask, uint32_t mem_type, uint32_t mem_prot) {
			return scan(rmt_handle, static_cast<byte*>(rmt_start_addr), static_cast<byte*>(rmt_end_addr), data, mask, mem_type, mem_prot);
		}

		// Scan memory of a remote process.
		inline void* scan(HANDLE rmt_handle, uint32_t rmt_start_addr, uint32_t rmt_end_addr, char* data, char* mask, uint32_t mem_type, uint32_t mem_prot) {
			return scan(rmt_handle, reinterpret_cast<byte*>(rmt_start_addr), reinterpret_cast<byte*>(rmt_end_addr), data, mask, mem_type, mem_prot);
		}

		// Finds the end of a remote function.
		// Works by scanning for prolog of next function.
		inline void* findFuncEnd(HANDLE rmt_handle, void* rmt_func) {
			return reinterpret_cast<void*>(reinterpret_cast<uint32_t>(scan(rmt_handle, reinterpret_cast<uint32_t>(rmt_func) + 1, UINT_MAX, const_cast<char*>("\x55\x8B\xEC"), const_cast<char*>("xxx"), MEM_ANY, PAGE_ANYREAD)) - 3);
		}

		// Calculates size of remote function.
		// Works by scanning for prolog of next function.
		inline size_t calcFuncSize(HANDLE rmt_handle, void* rmt_func) {
			return reinterpret_cast<size_t>(findFuncEnd(rmt_handle, rmt_func)) - reinterpret_cast<size_t>(rmt_func);
		}

		// Create a duplicate of a remote function within the remote process.
		// Does not patch calls/jmps/etc.
		void* duplicateFunc(HANDLE rmt_handle, void* rmt_func);

		// Create a duplicate of a remote function within the remote process.
		// Does not patch calls/jmps/etc.
		template <typename T>
		inline T duplicateFunc(HANDLE rmt_handle, void* rmt_func) {
			return duplicateFunc(rmt_handle, rmt_func);
		}

		// Create a duplicate of a remote function within the remote process.
		// Does not patch calls/jmps/etc.
		inline void* duplicateFunc(HANDLE rmt_handle, uint32_t rmt_func) {
			return duplicateFunc(rmt_handle, reinterpret_cast<void*>(rmt_func));
		}

		// Create a duplicate of a remote function within the remote process.
		// Does not patch calls/jmps/etc.
		template <typename T>
		inline T duplicateFunc(HANDLE rmt_handle, uint32_t rmt_func) {
			return duplicateFunc(rmt_handle, reinterpret_cast<void*>(rmt_func));
		}
	}
}

// Useful namespace aliases
#ifndef MEM_NO_ALIAS
namespace MemLocal = Memory::Local;
namespace MemRmt = Memory::Remote;
#endif