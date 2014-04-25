# DLL Inj3cti0n

Another dll injection tool.

## Overview

This tool is a implementation of differentes injection / execution of DLL.  
Test on : 
   - windows xp sp3 (use the token privilege for system process injection,) /!\ put the DLL at the same target process directory
   - windows seven (works on the same user session process)

The DLL that I used to inject different process is also present.  
I developed this tool in order to learn dll injection.  
Don't hesitate to help me to improve it.  

## Usage

```

C:\> inject.exe <DLL> <PID>

DLL : Path of the DLL
PID : PID of the targeted process

Example : 

C:\tmp> inject.exe dll.dll 42

```


## To do
  
  1. ~~CreateRemoteThread method~~
  2. ~~Without CreateRemoteThread() method (injection shellcode)~~
  3. ~~QueueUserAPC() method~~
  4. NtCreateThreadEx() method
  5. SetWindowsHookEx() method


## Links / Thanks to

  * http://msdn.microsoft.com/en-us/library/windows/desktop/ms684320(v=vs.85).aspx
  * http://msdn.microsoft.com/en-us/library/windows/desktop/ms683212(v=vs.85).aspx
  * http://msdn.microsoft.com/en-us/library/windows/desktop/aa366890(v=vs.85).aspx
  * http://msdn.microsoft.com/en-us/library/windows/desktop/ms681674(v=vs.85).aspx
  * http://msdn.microsoft.com/en-us/library/windows/desktop/ms682437(v=vs.85).aspx
  * http://msdn.microsoft.com/en-us/library/windows/desktop/aa446619(v=vs.85).aspx
  * http://msdn.microsoft.com/en-us/library/windows/hardware/ff541528(v=vs.85).aspx
  * http://www.ivanlef0u.tuxfamily.org/?p=40
  * http://resources.infosecinstitute.com/code-injection-techniques
  * http://syprog.blogspot.ca/2012/05/createremotethread-bypass-windows.html
  * http://www.ivanlef0u.tuxfamily.org/?p=395
  * http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html
  * http://www.codeguru.com/cpp/w-p/system/misc/article.php/c5667/API-Hooking-Revealed.htm
  * http://www.drdobbs.com/inside-nts-asynchronous-procedure-call/184416590
  * 

## Author

Security enthusiast, you can follow me on twitter [@nyx__o](https://twitter.com/nyx__o)

## License 

[GPL v3](../master/LICENSE)
