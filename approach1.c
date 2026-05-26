#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

// SSN for NtProtectVirtualMemory - resolved at runtime
static DWORD SSN_NtProtect = 0;

// Executable region holding our syscall trampoline
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

// Resolve SSN via neighbor: scan EAT neighbors +- offset until we hit a clean stub
// Syscall numbers in ntdll are sequential in EAT alphabetical order
static DWORD ResolveSSNByNeighbor(HMODULE hNtdll, DWORD targetNameIdx,
                                   PDWORD funcRVAs, PWORD nameOrdinals,
                                   DWORD numNames) {
    // Walk forward
    for (DWORD offset = 1; offset < 10; offset++) {
        if (targetNameIdx + offset >= numNames) break;
        PVOID neighbor = (PVOID)((PBYTE)hNtdll + funcRVAs[nameOrdinals[targetNameIdx + offset]]);
        DWORD ssn = ExtractSSN(neighbor);
        if (ssn != (DWORD)-1)
            return ssn - offset; // our SSN is neighbor's minus distance
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
// Returns pointer to executable stub memory
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

// Call NtProtectVirtualMemory directly via our stub using inline asm
// Avoids the x64 variadic calling convention problem entirely
static NTSTATUS DirectNtProtect(PVOID stub,
                                 HANDLE hProcess,
                                 PVOID *baseAddr,
                                 PSIZE_T regionSize,
                                 DWORD  newProt,
                                 PDWORD oldProt) {
    // x64 calling convention:
    // rcx = hProcess, rdx = baseAddr, r8 = regionSize, r9 = newProt
    // stack arg (5th) = oldProt
    // We jump to our stub which does: mov r10,rcx; mov eax,ssn; syscall; ret
    typedef NTSTATUS (NTAPI *FnProtect)(HANDLE, PVOID*, PSIZE_T, DWORD, PDWORD);
    return ((FnProtect)stub)(hProcess, baseAddr, regionSize, newProt, oldProt);
}

// Patch a hooked stub back to a clean syscall stub
static BOOL PatchStub(PVOID hookedFunc, DWORD ssn) {
    SIZE_T sz      = 11;
    DWORD  oldProt = 0;
    PVOID  target  = hookedFunc;

    BYTE cleanStub[] = {
        0x4C, 0x8B, 0xD1,                              // mov r10, rcx
        0xB8, (BYTE)ssn, (BYTE)(ssn >> 8), 0x00, 0x00, // mov eax, ssn
        0x0F, 0x05,                                    // syscall
        0xC3                                           // ret
    };

    // Make page writable via our direct stub, not the hooked NtProtect
    NTSTATUS st = DirectNtProtect(g_StubMem,
                                  GetCurrentProcess(),
                                  &target, &sz,
                                  PAGE_EXECUTE_READWRITE,
                                  &oldProt);
    if (!NT_SUCCESS(st)) {
        printf("[-] NtProtect failed for %p status=%08lX\n", hookedFunc, st);
        return FALSE;
    }

    memcpy(hookedFunc, cleanStub, sizeof(cleanStub));

    // Restore original page protection
    DirectNtProtect(g_StubMem,
                    GetCurrentProcess(),
                    &target, &sz,
                    oldProt, &oldProt);

    return TRUE;
}

int main(void) {
    // ntdll is always mapped, GetModuleHandle won't call LoadLibrary
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        return 1;
    }

    // DOS header sits at the module base, e_lfanew points to the PE header
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + dos->e_lfanew);

    // DataDirectory[0] is always the export directory RVA
    DWORD expRVA = nth->OptionalHeader
                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                       .VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY expDir =
        (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hNtdll + expRVA);

    // AddressOfNames: array of RVAs to null-terminated export name strings
    PDWORD nameRVAs     = (PDWORD)((PBYTE)hNtdll + expDir->AddressOfNames);
    // AddressOfFunctions: array of RVAs to the actual function code
    PDWORD funcRVAs     = (PDWORD)((PBYTE)hNtdll + expDir->AddressOfFunctions);
    // AddressOfNameOrdinals: maps name index -> function array index
    PWORD  nameOrdinals = (PWORD) ((PBYTE)hNtdll + expDir->AddressOfNameOrdinals);
    DWORD  numNames     = expDir->NumberOfNames;

    // First pass: resolve SSN for NtProtectVirtualMemory
    // We need this before we can patch anything else
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

    if (SSN_NtProtect == 0 || SSN_NtProtect == (DWORD)-1) {
        printf("[-] Failed to resolve NtProtectVirtualMemory SSN\n");
        return 1;
    }

    // Allocate and build our direct syscall trampoline for NtProtect
    g_StubMem = AllocateSyscallStub(SSN_NtProtect);
    if (!g_StubMem) {
        printf("[-] Failed to allocate syscall stub\n");
        return 1;
    }
    printf("[+] Syscall stub allocated @ %p\n", g_StubMem);

    int patched = 0;
    int failed  = 0;

    // Second pass: find and patch all hooked Nt* stubs
    for (DWORD i = 0; i < numNames; i++) {
        LPCSTR name = (LPCSTR)((PBYTE)hNtdll + nameRVAs[i]);

        // Only check Nt* syscall stubs
        if (strncmp(name, "Nt", 2) != 0) continue;

        PVOID addr = (PVOID)((PBYTE)hNtdll + funcRVAs[nameOrdinals[i]]);
        if (!IsHooked(addr)) continue;

        // nameOrdinals[i] gives the index into funcRVAs for this name
        DWORD ssn = ResolveSSNByNeighbor(hNtdll, i,
                                          funcRVAs, nameOrdinals,
                                          numNames);
        if (ssn == (DWORD)-1) {
            printf("[-] Could not resolve SSN for %s\n", name);
            failed++;
            continue;
        }

        printf("[*] Patching %-40s SSN=0x%02lX\n", name, ssn);

        if (PatchStub(addr, ssn))
            patched++;
        else
            failed++;
    }

    printf("\n[+] Done. patched=%d failed=%d\n", patched, failed);

    // Keep process alive so you can attach WinDbg and verify
    printf("[*] Sleeping 60s - attach WinDbg and run: u ntdll!NtOpenProcess\n");
    Sleep(60000);

    VirtualFree(g_StubMem, 0, MEM_RELEASE);
    return 0;
}
