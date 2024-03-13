# APCGO
This is a module which allows for APC Injection into a remote process written in go, encryption and decryption of a payload, and some staging. it contains a few evasive techniques, nothing novel. Educational purposes only im not liable for what you do with it. 

# Packages in `pkg` directory

This directory contains the following packages:

## `encryption`

This package provides functions for AES-256 encryption and decryption. It includes functions for padding data, converting byte slices to strings of hex values, reading payloads to files, and reading files to extract components or without extracting components.

Key functions include:
- `Aes256`: Encrypts the data with the key and returns the encrypted data and IV.
- `EncryptPayload`: Encrypts the payload with the key and returns the encrypted payload, IV, and key.
- `ReadPayloadToFile`: Writes the payload to a file.
- `ReadFileAndExtractComponents`: Reads data from the file, extracts the key, IV, and payload.
- `ReadFileWithoutComponents`: Reads data from the file without separating the key, IV, and payload.
- `DecryptAES`: DecryptAES decrypts a ciphertext using the given key and IV

## `selfdelete`

This package provides functions for self-deleting executables in Windows. It includes functions for opening a handle to the file to be deleted, renaming the file to a random stream name, marking the file to be deleted on close, and deleting the current running executable.

Key functions include:
- `SelfDeleteExe`: Deletes the current running executable.


## `stalling`
This package contains `CalculatePrimes` which is used to delay execution in sandbox environments


## `injection`
This package executes shellcode in a child process using the following steps:
 1. Create a child proccess in a suspended state with CreateProcessW
 2. Allocate RW memory in the child process with VirtualAllocEx
 3. Write shellcode to the child process with WriteProcessMemory
 4. Change the memory permissions to RX with VirtualProtectEx
 5. Add a UserAPC call that executes the shellcode to the child process with QueueUserAPC
 6. Resume the suspended program with ResumeThread function

- `inject`: injects shellcode into a remote process.

