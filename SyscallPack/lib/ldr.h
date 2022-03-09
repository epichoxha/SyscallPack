#include <windows.h>

#define DEREF(name) *(UINT_PTR*)(name)
#define DEREF_64(name) *(DWORD64*)(name)
#define DEREF_32(name) *(DWORD*)(name)
#define DEREF_16(name) *(WORD*)(name)
#define DEREF_8(name) *(BYTE*)(name)
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define MAX_SYSCALL_STUB_SIZE 64
#ifndef NT_SUCCESS
#define NT_SUCCESS(StatCode)  ((NTSTATUS)(StatCode) >= 0)
#endif


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING  ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID*    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef void* PRTL_USER_PROCESS_PARAMETERS;

typedef void* PPS_POST_PROCESS_INIT_ROUTINE;

typedef struct _PEB_LDR_DATA {
	DWORD dwLength;
	DWORD dwInitialized;
	LPVOID lpSsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;

typedef struct {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * LLDR_DATA_TABLE_ENTRY;



typedef NTSTATUS(NTAPI* _NtOpenSection)(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*);

typedef NTSTATUS(NTAPI* _NtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

typedef NTSTATUS(NTAPI* _NtUnmapViewOfSection)(HANDLE, PVOID);

typedef VOID(NTAPI* _RtlInitUnicodeString)(PUNICODE_STRING , PCWSTR);

typedef NTSTATUS(WINAPI *_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);

typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(HANDLE, PVOID, PSIZE_T, ULONG, PULONG);

typedef NTSTATUS(WINAPI *_NtClose)(HANDLE);