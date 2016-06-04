# tdi_monitor
Monitoring Network Behaviors by Transport Driver Interface (TDI)

This is a course project for Windows Security (IS405) in SJTU, 2016 spring semester.

## Platform
+ OS:             Microsoft Windows XP SP3
+ Editor:         Sublime Text 3
+ Compiler:       WinDDK 7600.16385.1
+ Debugger:       DebugView 4.64
+ Driver Installer: SRVINSTW

## Terminology
1. *Transport Driver Interface (TDI)*
    
    The Transport Driver Interface (TDI) defines a kernel-mode network interface that is exposed at the upper edge of all transport protocol stacks. The highest level protocol driver in every such stack supports the TDI interface for still higher level kernel-mode network clients. When user-mode binaries are created by compiling and linking, an entity called a TDI client is linked into the binary. TDI clients are provided with the compiler. The user-mode binary uses the user-mode API of whatever network protocol is being used, which in turn causes the TDI client to emit TDI commands into the Transport Provider.

2. *I/O request packets (IRPs)*
    
    I/O request packets are kernel mode structures that are used by Windows Driver Model (WDM) and Windows NT device drivers to communicate with each other and with the operating system. They are data structures that describe I/O requests, and can be equally well thought of as "I/O request descriptors" or similar. Rather than passing a large number of small arguments (such as buffer address, buffer size, I/O function type, etc.) to a driver, all of these parameters are passed via a single pointer to this persistent data structure. The IRP with all of its parameters can be put on a queue if the I/O request cannot be performed immediately. I/O completion is reported back to the I/O manager by passing its address to a routine for that purpose, IoCompleteRequest. The IRP may be repurposed as a special kernel APC object if such is required to report completion of the I/O to the requesting thread.

### Intro
Three projects included are `tdi_fw`, `m_quick_filter` and `hook`. 

tdi_fw is the famous open source personal firewall using TDI, and serves as the reference in this repo. The rest both realized the function to monitor network flow and log tinto DbgView as a registered driver but in different ways.

+ `m_quick_filter` rewrote `quick_filter` module in `tdi_fw`.

+ `hook` hooked on `DriverEntry` and parsed frames into IRPs which can be called by IRP stack pointer and then extracting dst., src., prt. and etc. from them.

### Usage
1. In WinDDK:
 
        > cd ${project_path};
        > build;

2. In SRVINSTW:  

        install ${driver_path}/m_quick_filter.sys | hook.sys;

3. Logging in DbgView;


