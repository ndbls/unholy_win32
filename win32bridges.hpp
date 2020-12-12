#pragma once
#include <Windows.h>

//  ---------------------------
//  |    IMPORTANT MESSAGE    |
//  ---------------------------
//
// When compiling your programs (in debug mode especially) ensure the
// following options are set...
//   /std:c++17 /RTCu /INCREMENTAL:NO
// Otherwise the portables can't be cleanly copied over to the remote
// process, and the bridges can't get relocated. You will crash if
// you don't ensure these are set. You can't compile at all without
// c++17 though, because this library uses fold expressions.
//
// :)


// Essential macro that allows you to encode a list of types into argument data to be accepted by bridge
// creation functions.
#define BRIDGE_ARGS(...) Bridges::_typeInfo<__VA_ARGS__>()

// Possible function types bridges can be created for.
enum Func_t {
	TFUNC_CDECL,            // cdecl that returns a non-floating-point 4-byte value
	TFUNC_CDECL_RTN64,      // cdecl that returns an __int64
	TFUNC_CDECL_RTNFLT,     // cdecl that returns a float
	TFUNC_CDECL_RTNDBL,     // cdecl that returns a double
	TFUNC_STDCALL,          // stdcall that returns a non-floating-point 4-byte value
	TFUNC_STDCALL_RTN64,    // stdcall that returns an __int64
	TFUNC_STDCALL_RTNFLT,   // stdcall that returns a float
	TFUNC_STDCALL_RTNDBL,   // stdcall that returns a double
	TFUNC_FASTCALL,         // fastcall that returns a non-floating-point 4-byte value
	TFUNC_FASTCALL_RTN64,   // fastcall that returns an __int64
	TFUNC_FASTCALL_RTNFLT,  // fastcall that returns a float
	TFUNC_FASTCALL_RTNDBL   // fastcall that returns a float
};

namespace Bridges {
	// TODO: _typeInfo could use a little touch up for efficiency but fold expressions make me sad when I debug and I have been busyy... I will get around to it....
	// I found this snippet on github that I think tbh could help replace the whole typeinfo cancer:
	//		std::uint64_t arr_args[sizeof...(args) > 4 ? sizeof...(args) : 4] = { (std::uint64_t)(args)... };

	// Internal function used by the macro BRIDGE_ARGS() to encode information about the given arguments into a 32-bit integer value.
	template <typename... Args>
	int _typeInfo() {
		int first_progress_mask = 0xffffffff;
		int first_slot_idx = ( ( (sizeof(Args) <= sizeof(int)) ? (first_progress_mask = 0) : ((int)(sizeof(Args) / sizeof(int))) & first_progress_mask ) + ... );
		
		bool second_progress_skip = 1;
		int second_progress_mask = 0xffffffff;
		int second_slot_idx = ( ( (sizeof(Args) <= sizeof(int)) ? ( second_progress_skip ? ((second_progress_skip = 0), 1) : ((second_progress_mask = second_progress_skip), 0) ) : ((int)(sizeof(Args) / sizeof(int))) & second_progress_mask ) + ... );
		
		int nslots = (( (sizeof(Args) < sizeof(int)) ? (1) : (sizeof(Args) / sizeof(int)) ) + ...);
		
		if (first_slot_idx >= nslots)
		    first_slot_idx = 0xff;
		if (second_slot_idx >= nslots)
		    second_slot_idx = 0xff;
		
		return ((second_slot_idx & 0xff) << 16) | ((first_slot_idx & 0xff) << 8) | (nslots & 0xff);
	}

	// Base bridge creation function. You can use it but the top-level creators are nicer to conceptualize when writing code.
	void* _createBridge(HANDLE rmt_handle, void* target_func, int func_type, int arg_info, bool reverse_bridge);

	// Create a bridge to a remote function.
	// Returns address of a local function that when called, calls the remote target function with the
	// args you specify and returns the return value from the remote function.
	inline void* createBridgeRmt(HANDLE rmt_handle, void* rmt_target_func, int func_type, int arg_info) {
		return _createBridge(rmt_handle, rmt_target_func, func_type, arg_info, false);
	}

	// Create a bridge to a remote function.
	// Returns address of a local function that when called, calls the remote target function with the
	// args you specify and returns the return value from the remote function.
	inline void* createBridgeRmt(HANDLE rmt_handle, int rmt_target_func, int func_type, int arg_info) {
		return _createBridge(rmt_handle, reinterpret_cast<void*>(rmt_target_func), func_type, arg_info, false);
	}

	// Create a bridge to a remote function.
	// Returns address of a local function that when called, calls the remote target function with the
	// args you specify and returns the return value from the remote function.
	template <typename T>
	inline T createBridgeRmt(HANDLE rmt_handle, void* rmt_target_func, int func_type, int arg_info) {
		return reinterpret_cast<T>(_createBridge(rmt_handle, rmt_target_func, func_type, arg_info, false));
	}

	// Create a bridge to a remote function.
	// Returns address of a local function that when called, calls the remote target function with the
	// args you specify and returns the return value from the remote function.
	template <typename T>
	inline T createBridgeRmt(HANDLE rmt_handle, int rmt_target_func, int func_type, int arg_info) {
		return reinterpret_cast<T>(_createBridge(rmt_handle, reinterpret_cast<void*>(rmt_target_func), func_type, arg_info, false));
	}

	// Create a bridge to a local function.
	// Returns remote address of a remote function that when called by the remote process, calls the local target function with the
	// args you specify and returns the return value from the local function.
	inline void* createBridgeLocal(HANDLE rmt_handle, void* local_target_func, int func_type, int arg_info) {
		return _createBridge(rmt_handle, local_target_func, func_type, arg_info, true);
	}

	// Create a bridge to a local function.
	// Returns remote address of a remote function that when called by the remote process, calls the local target function with the
	// args you specify and returns the return value from the local function.
	inline void* createBridgeLocal(HANDLE rmt_handle, int local_target_func, int func_type, int arg_info) {
		return _createBridge(rmt_handle, reinterpret_cast<void*>(local_target_func), func_type, arg_info, true);
	}

	// Create a bridge to a local function.
	// Returns remote address of a remote function that when called by the remote process, calls the local target function with the
	// args you specify and returns the return value from the local function.
	template <typename T>
	inline T createBridgeLocal(HANDLE rmt_handle, void* local_target_func, int func_type, int arg_info) {
		return reinterpret_cast<T>(_createBridge(rmt_handle, local_target_func, func_type, arg_info, true));
	}

	// Create a bridge to a local function.
	// Returns remote address of a remote function that when called by the remote process, calls the local target function with the
	// args you specify and returns the return value from the local function.
	template <typename T>
	inline T createBridgeLocal(HANDLE rmt_handle, int local_target_func, int func_type, int arg_info) {
		return reinterpret_cast<T>(_createBridge(rmt_handle, reinterpret_cast<void*>(local_target_func), func_type, arg_info, true));
	}
}