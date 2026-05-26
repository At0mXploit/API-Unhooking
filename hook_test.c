#include <windows.h>
#include <stdio.h>
#include <string.h>

// Check if function starts with a JMP (0xE9) indicating a hook
BOOL IsHooked(PVOID funcAddr) {
    return *(PBYTE)funcAddr == 0xE9;
}

// Get the destination address of a JMP hook
PVOID GetHookTarget(PVOID funcAddr) {
    DWORD relOffset = *(PDWORD)((PBYTE)funcAddr + 1);
    return (PVOID)((PBYTE)funcAddr + 5 + relOffset);
}

// Walk ntdll's EAT and report hooked Nt* functions
void DetectHooks(void) {
    // ntdll is always mapped, GetModuleHandle won't call LoadLibrary
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        return;
    }

    // DOS header sits at the module base, e_lfanew points to the PE header
    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHdrs = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + dosHdr->e_lfanew);

    // DataDirectory[0] is always the export directory RVA
    DWORD exportDirRVA = ntHdrs->OptionalHeader
                             .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                             .VirtualAddress;

    // RVA + module base = VA of the export directory struct
    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)hNtdll + exportDirRVA
    );

    // AddressOfNames: array of RVAs to null-terminated export name strings
    PDWORD nameRVAs     = (PDWORD)((PBYTE)hNtdll + expDir->AddressOfNames);
    // AddressOfFunctions: array of RVAs to the actual function code
    PDWORD funcRVAs     = (PDWORD)((PBYTE)hNtdll + expDir->AddressOfFunctions);
    // AddressOfNameOrdinals: maps name index -> function array index
    PWORD  nameOrdinals = (PWORD) ((PBYTE)hNtdll + expDir->AddressOfNameOrdinals);

    int hookedCount = 0;

    printf("[*] Scanning ntdll exports for hooks...\n\n");

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        // Resolve the export name from its RVA
        LPCSTR name = (LPCSTR)((PBYTE)hNtdll + nameRVAs[i]);

        // Only check Nt* syscall stubs
        if (strncmp(name, "Nt", 2) != 0)
            continue;

        // nameOrdinals[i] gives the index into funcRVAs for this name
        PVOID funcAddr = (PVOID)((PBYTE)hNtdll + funcRVAs[nameOrdinals[i]]);

        if (IsHooked(funcAddr)) {
            PVOID target = GetHookTarget(funcAddr);
            printf("[HOOKED] %-40s at %p -> jmp %p\n", name, funcAddr, target);
            hookedCount++;
        }
    }

    printf("\n[*] Scan complete. %d hook(s) found.\n", hookedCount);
}

int main(void) {
    DetectHooks();
    return 0;
}
