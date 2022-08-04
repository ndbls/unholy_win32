# ⛧ Unholy Win32  ⛧

Unholy is a C++17 library that provides you with some fun hax on x86 Windows systems.

It is essentially a standard and minimal memory debugging library, except it features a unique set of tools which allow for seamless function calls with wrapped return values across process boundaries, nicknamed *bridges*.

It can be difficult to understand the purpose and power of this library from just explanations without an example, so here's a very easy to digest, simplified use case of this unholy library:

>You have program `wallet_application.exe` and program `hacker.exe`. The latter program contains the unholy library, and it uses unholy bridges to call the function `int transferMoney(int recipientId, int amount)` which is internal to `wallet_application.exe`.

Of course that is a dramatic example, but this library is flexible and the applications could be anything, such as `game.exe` and `cheat.exe` calling `void setHealth(int value)` completely externally. Bridges can also be in reverse, functioning like a callback from a remote process to a local function:

>You have a program `enigma.exe` that you did not create, and a program `security_researcher.exe` you have created. You would like to reverse engineer what `enigma.exe` does. You use unholy reverse bridges to create functions inside `engima.exe` while it is running that call back to logging functions you created inside `security_researcher.exe`. You use unholy hooks to hook winapi functions to point to your reverse bridges and build a log of intercepted winapi calls that allow you to better understand the functioning of `enigma.exe`.

No traditional methods of code injection are required in these examples, all of this can be done without having to leave your local program. No need to create a DLL or use an injector.

Unholy Win32 also has everything one would expect from a regular memory debugging library,
  - Hooking of local and remote functions
  - Scanning of local and remote process memory space
  - Utilities for easy manipulation of remote process memory

However...
These memory manipulation tools, while useful, are not the star of unholy win32.
The superstar of this library is the **much** more powerful collection of features in the bridge toolset.

# Bridges are the key feature 🔑
What exactly are bridges?
  - A bridge function is essentially a function in your program's local process which is bound to a specific function in a remote process you set during the bridge creation, and the bridge will emulate that remote function **as if the bridge *is* the remote function magically accessible from the local process**. It receives the same arguments the remote function would, and it handles all of the complicated actions that go into making the remote call happen and returning the remote return value. In most cases, the caller of the bridge does not even have to be aware it is interacting with a bridge.

  - **Bridges can also be created in remote processes as a bridge to a local function**, allowing for callback functions in remote processes which when called by that process, can call local functions without the remote process having the knowledge that it is interacting with a bridge. These can be referred to as *reverse bridges*.

This is extremely useful for programs that would otherwise inject code into another process in order to modify its behavior or to hook functions to aid in reverse engineering (since unholy memory tools contain hooking functions).

## How do I use this?
Just import the files into your C++ project.

If you just want memory scanning/hooking, only copy `win32memory.hpp` and `win32memory.cpp` into your project and the library can still function . If you want to use `win32bridges`, then you must copy all four files into your project, as `win32bridges` cannot operate without the `win32memory` files.  

**If you include bridges, ensure you set `/std:c++17 /RTCu /INCREMENTAL:NO` in your compiler.** See the comment at the top of `win32bridges.hpp` for more details.

This library can only be compiled with x86 MSVC due to the nature of how targeted it is, specifically bridges.
It might compile with other tools if given a little bit of work, but it has not been tested.

You should check out the [example projects](https://github.com/abls/unholy_examples) to better understand how to use bridges and the memory tools. The examples are very organized and straightforward, with comments, so it shouldn't be too difficult to understand. All of the functions are well documented with comments as well. Also check out the [simple example](#simple-bridge-example) below in this file.

## FAQs
> So like... What does it do?

Unholy Win32 let's you, among other things, easily call functions you aren't supposed to in a process you do not have control of. You can also create remote callbacks to local functions. It lets you do some memory scanning and patching as well, but that's not the main focus of the library.

> Well, what could this be used for?

A whole lot! One legitimate use might be a logging system where you hook remote functions to a reverse bridge that calls back to the local process (think like DLL injection + MS detours). Other uses might be debugging, reverse engineering, malware, or game cheats.

> How are bridges different from DLL injection?

So, it's actually fairly similar but arguably more lightweight. Definitely check out the source code if you want to know more, but at a very high level bridges work a lot like manual mapping. Unlike manual mapping, bridges avoid loading an entire DLL and instead they allocate and write to a *very* tiny region of memory in the remote process that acts as a gateway, or a probe, into the remote process. This region only briefly remains allocated for the duration of the function call as well.

It's also much easier to use bridges than DLL injection, as you don't have to compile and manage a separate DLL and mess with injectors. In just a few lines using unholy win32, you can hook a function in a remote process, intercept the arguments, and do whatever you want with the return value (you can even call the original function), all without having to leave the comfort of your local process.

## Simple bridge example
This example is broken up into two programs, since the function of bridges is to enable complex interaction between different processes.

This first program is the target program whose run-time behavior will be getting modified by our unholy program.
```c++
// main.cpp - target.exe (the program getting dynamically modified)
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

This is the unholy program that will be modifying the behavior of the target program while it is running.
```c++
// main.cpp - hacker.exe (program that modifies the target program's behaviour)
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
    
    // If you are wondering, createBridgeLocal is how you would create a bridge
    // from a remote process to a local function. Rmt isn't the only option.

    // Now we can call the bridge
    int rtn_val = hello(my_name);

    // Print out the return value (should be 7, like we wrote in the target's main.c)
    printf("remote hello's return value: %d\n", rtn_val);
    
    return 0;
}
```

If anything is unclear, check out the much more developed [examples](https://github.com/abls/unholy_examples). You should also take a peek at the source code. There is some really useful information in the comments, generally organized underneath some ascii art headers, that should clear up any questions you have.

### Todos
 - Benchmarks
 - Bridge destruction
 - One-time remote call function that does not build an entire bridge, just calls a function
 - Flesh out the hooks to have a variety of different hooking methods
