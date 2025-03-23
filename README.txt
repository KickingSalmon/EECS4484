This is a program that resembles malware and is not actually malware itself.
It does nothing malicious. For Educational Purposes Only.

Command to Compile final.c into Final.exe:
gcc Sean-Malware.c -o Sean.malware.exe -lws2_32

Flags to provide to .exe file in order for the program to demostrate different
capabilities:

-r: Process Hollowing
-p: Run on Startup
-c: Connect to a C2 Server (Non-hidden Flag. Able to see with Strings)
-e: Encoding and Hides A hidden flag (Unable to see with Strings)
-d: Checks to see if running in a Debugger
-h: Checks to see if running in a Hypervisor

Packed with UPX
