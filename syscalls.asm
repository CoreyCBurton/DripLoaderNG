.CODE

EXTERN SyscallInst:QWORD

makeSyscall proc
	; Argument handling
	mov r10, rcx

	; jmp to "syscall"
	jmp QWORD PTR [SyscallInst]
makeSyscall endp


NtQueryVirtualMemory proc
	; Specify the syscall number
	mov eax, 23h

	jmp makeSyscall
NtQueryVirtualMemory endp

NtAllocateVirtualMemory proc
	; Specify the syscall number
	mov eax, 18h

	jmp makeSyscall
NtAllocateVirtualMemory endp

NtProtectVirtualMemory proc
	; Specify the syscall number
	mov eax, 50h

	jmp makeSyscall
NtProtectVirtualMemory endp

END
