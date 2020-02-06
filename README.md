# ⛧ Unholy Win32  ⛧

Unholy is a C++17 library enabling some powerful hacks within x86 Windows systems.
It is essentially a standard memory hacking library, except it features a unique set of tools which allow for function calls across process boundaries, nicknamed *bridges*.

It has everything one would expect from a memory hacking library,
  - Hooking of local and remote functions
  - Scanning of local and remote process memory space
  - Utilities for easy manipulation of remote process memory

However...
These memory manipulation tools, while useful, are not the star of unholy win32.
The superstar of this library is the **much** more powerful collection of features in the bridge toolset.

# Bridges are the key feature 🔑
What are bridges?
  - A bridge is a function that, when called, can seamlessly call a function in a remote process and wrap that function's return value to the local process as if the bridge itself were somehow the remote function, but accessible locally. Callers of bridge functions call the bridge function like they would a regular function in their local address space, and the caller does not have be aware it is calling a bridge function.
  - Bridges can also be created in remote processes as a bridge to a local function, allowing for callback functions in remote processes which when called by that process, can call local functions without the remote process having the knowledge that it is interacting with a bridge.

This is extremely useful for programs that would otherwise inject code into another process in order to modify its behaviour. It is an extremely lightweight alternative to any method of code injection, and it is also much less detectable as the bridges only keep (a *very* small amount of) memory allocated in the remote process during the period of time they are running that gets cleaned up once the bridge returns.

## How do I use this?
Just import the files into your C++ project. If you include bridges, make sure you are compiling with c++17 and with the options specified at the top of `win32bridges.hpp`. This library can only be compiled with x86 MSVC due to the nature of how targeted it is, specifically bridges.

You should check out the [example projects](https://github.com/abls/unholy_examples) to better understand how to use bridges and the memory tools. The examples are very organized and straightforward, with comments, so it shouldn't be too difficult to understand. All of the functions are well documented with comments as well.

Here's a simple example of bridges just to give you a taste before you check out the example projects...

## Simple bridge example
This example is broken up into two programs, since the function of bridges is to enable complex interaction between different processes.

This first program is the target program that will be getting modified by our unholy program.
```c++
// main.c - target.exe (the program getting dynamically modified)
#include <stdio.h>
#include <Windows.h>

// This is the function that we will call from our unholy program.
int hello(char* name) {
    printf("Hello, %s!", name);
    return 7;
}

int main() {
    hello("user");
    Sleep(INFINITE);
    return 0;
}
```

This is the unholy program that will be modifying the target program while it is running.
```c++
// main.c - hacker.exe (program that modifies the target program's behaviour)
#include <stdio.h>
#include <Windows.h>
#include "unholy/win32memory.hpp"
#include "unholy/win32bridges.hpp"

#define MOD_NAME "target.exe"
#define OFF_HELLO 0xBEEF  // Offset of the target function from module base
                          // address in target process.

// Just typedef the function signature of the target function for convenience.
typedef int(__cdecl* hello_t)(char* name);

int main() {
    // Get necessary info about the process...
    uint32_t rmt_pid = MemRmt::getPid(MOD_NAME);
    HANDLE rmt_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, rmt_pid);
    uint32_t img_base_addr = MemRmt::getModBase(rmt_pid, MOD_NAME);
    
    // We need to allocate a string in the remote process so that the remote
    // function can use it when we pass it.
    char* my_name = MemRmt::allocWriteString(rmt_handle, "hacker");

    // Before we can use a bridge, we have to create one!
    // The template parameter is just a shortcut that casts for us btw.
    hello_t hello = Bridges::createBridgeRmt<hello_t>(
        rmt_handle,                 // Handle to the target process.
        img_base_addr + OFF_HELLO,  // Address of target function.
        TFUNC_CDECL,                // Constant representing function type.
                                    // It can be one of TWELVE values making up different
                                    // variations of cdecl, stdcall, and fastcall.
        BRIDGE_ARGS(char*)          // This is a special macro that will generate
    );                              // encoded argument info from a list of types.
    
    // Now we can call the bridge
    int rtn_val = hello(my_name);

    // Print out the return value (should be 7, like we wrote in the target's main.c)
    printf("remote hello's return value: %d\n", rtn_val);
    
    return 0;
}
```

If anything is unclear, take a peek at the source code or look at the [examples](https://github.com/abls/unholy_examples). There is some really useful information in the comments underneath organized ascii art headers that should clear up any questions you have.

### Todos
 - Benchmarks
 - Bridge destruction
 - One-time remote call function that does not build an entire bridge, just calls a function