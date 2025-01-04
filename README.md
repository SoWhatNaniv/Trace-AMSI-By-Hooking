# Amsi-Hooking
Tool that traces AMSI events using hooking without any Provider nor ETW and saves all buffers

![AmsiHook.dll POC](https://github.com/SoWhatNaniv/Amsi-Hooking/blob/main/Amsi%20Hooking.gif)


Instead of using ETW or Provider to trace AMSI events for malware analysis, I've created a dll
that hooks amsi dll main scaning functions and logging those buffers into designated log file.

Hooked also CreateProcessW to be able to trace process children and create their relevant log files.

