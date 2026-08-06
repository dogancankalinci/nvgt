/* anticheat.cpp - implementation of basic anti-cheat measures
 *
 * NVGT - NonVisual Gaming Toolkit
 * Copyright (c) 2022-2026 Sam Tupy
 * https://nvgt.dev
 * This software is provided "as-is", without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 * 1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
*/

#include "anticheat.h"
#ifdef _WIN32
#include <windows.h>
#include <winsvc.h> // service control manager; vm_check_registry() asks whether a driver is actually running.
#include <psapi.h>
#include <winternl.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <dxgi.h>
#elif defined(__APPLE__)
#include <TargetConditionals.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <csignal>
#include <csetjmp>
#else
#include <unistd.h>
#include <dirent.h>
#include <csignal>
#include <csetjmp>
#endif
#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
#define NVGT_HAS_X86_CPUID 1
#ifdef _MSC_VER
#include <intrin.h> // for __cpuidex; other toolchains use inline assembly instead.
#endif
#endif
#include <string>
#include <string_view>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <atomic>
#include <angelscript.h>
#include <cassert>
#include <array>

#ifdef _WIN32
static LPVOID mem_addr = nullptr;
static PSAPI_WORKING_SET_EX_INFORMATION working_set_information;
static PVOID ldr_dll_cookie = nullptr;
#ifdef __cplusplus
extern "C" {
#endif
static constexpr ULONG LDR_DLL_NOTIFICATION_REASON_LOADED = 1;
static constexpr ULONG LDR_DLL_NOTIFICATION_REASON_UNLOADED = 2;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
	ULONG Flags;					//Reserved.
	PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
	PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
	PVOID DllBase;				  //A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;			  //The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
	ULONG Flags;					//Reserved.
	PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
	PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
	PVOID DllBase;				  //A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;			  //The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID (NTAPI *PLDR_DLL_NOTIFICATION_FUNCTION)(ULONG, const PLDR_DLL_NOTIFICATION_DATA, PVOID);
#ifdef __cplusplus
}
#endif
using PFN_LdrRegisterDllNotification = NTSTATUS (NTAPI*)(ULONG, PLDR_DLL_NOTIFICATION_FUNCTION, PVOID, PVOID*);
using PFN_LdrUnregisterDllNotification = NTSTATUS (NTAPI*)(PVOID);
static PFN_LdrRegisterDllNotification pfn_ldr_register   = nullptr;
static PFN_LdrUnregisterDllNotification pfn_ldr_unregister = nullptr;
#endif
std::atomic_flag memory_scan_detected;
std::atomic_flag speed_hack_detected;
std::atomic_flag is_on_wine;

#ifdef _WIN32
#if defined(__x86_64__) || defined(_M_X64) || defined(__amd64__)
uint8_t safe_read(const uint8_t* addr) {
	__try {
		return *reinterpret_cast<volatile const uint8_t*>(addr);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return 0xFF;
	}
}
#elif defined(__aarch64__) || defined(_M_ARM64) || defined(__arm64__)
bool safe_read32(const uint32_t* addr, uint32_t& out) {
	__try {
		out = *reinterpret_cast<volatile const uint32_t*>(addr);
		return true;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}
#endif

bool is_executable(void* address) {
	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQuery(address, &mbi, sizeof(mbi))) return false;
	return (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE);
}

#if defined(__x86_64__) || defined(_M_X64) || defined(__amd64__)
bool is_modrm_jump(uint8_t opcode, uint8_t modrm) {
	const uint8_t op = opcode;
	const uint8_t mod = (modrm & 0b11000000) >> 6;
	const uint8_t reg = (modrm & 0b00111000) >> 3;
	// FF /4 is near jump, FF /5 is far jump
	return (op == 0xFF && (reg == 4 || reg == 5));
}

bool is_fnop(const uint8_t* bytes) {
	return bytes[0] == 0xD9 && bytes[1] == 0xD0;
}

bool is_nop(const uint8_t* bytes) {
	if (bytes[0] == 0x90) return true;				  // 1-byte NOP
	if (bytes[0] == 0x66 && bytes[1] == 0x90) return true; // 2-byte NOP
	if (bytes[0] == 0x0F && bytes[1] == 0x1F) return true; // multi-byte NOP
	if (bytes[0] >= 0x40 && bytes[0] <= 0x4F && bytes[1] == 0x90) return true; // REX-prefixed NOP
	return false;
}
#endif

bool is_function_hooked(void* func_ptr) {
	if (!is_executable(func_ptr)) {
		return true;
	}

#if defined(__x86_64__) || defined(_M_X64) || defined(__amd64__)
	const uint8_t* p = reinterpret_cast<const uint8_t*>(func_ptr);
	size_t offset = 0, n_nops = 0;

	// Skip leading NOPs (up to 16 bytes)
	while (offset < 16 && is_nop(p + offset)) {
		offset++;
		n_nops++;
	}

	// JMP rel8
	if (p[offset] == 0xEB) {
		return true;
	}

	// JMP rel16 or rel32
	if (p[offset] == 0xE9) {
		return true;
	}

	// FAR JMP absolute
	if (p[offset] == 0xEA) {
		return true;
	}

	// JMP r/mX (FF /4 or FF /5)
	if (p[offset] == 0xFF && is_modrm_jump(p[offset], p[offset + 1])) {
		return true;
	}

	// MOV RAX, imm64; JMP RAX (far jmp)
	if (p[offset] == 0x48 && p[offset + 1] == 0xB8 && p[offset + 10] == 0xFF && p[offset + 11] == 0xE0) {
		return true;
	}

	// INT3
	if (p[offset] == 0xCC) {
		return true;
	}

	// RET
	if (p[offset] == 0xC3) {
		return true;
	}

	// FNOP (floating-point NOP)
	if (is_fnop(p + offset)) {
		return true;
	}

	// Suspiciously many NOPs at start
	// This is more of a heuristic guess
	if (n_nops >= 5) {
		return true;
	}
#elif defined(__aarch64__) || defined(_M_ARM64) || defined(__arm64__)
	constexpr uint32_t ARM64_NOP	 = 0x1F2003D5;
	constexpr uint32_t ARM64_RET	 = 0xD65F03C0;
	constexpr uint32_t ARM64_BRK	 = 0xD4200000; // BRK #0
	uint32_t instr[4] = {};
	for (int i = 0; i < 4; ++i) {
		if (!safe_read32(((uint32_t*)func_ptr) + i, instr[i])) {
			return true;
		}
	}

	// Early RET
	if (instr[0] == ARM64_RET) {
		return true;
	}

	// BRK
	if ((instr[0] & 0xFFFFF000) == ARM64_BRK) {
		return true;
	}

	// LDR Xt, #imm + BR Xt (common hook: load addr + jump)
	if ((instr[0] & 0xFFC00000) == 0x58000000 && (instr[1] & 0xFFFFFC1F) == 0xD61F0000) {
		return true;
	}

	// Absolute branch (B, BL)
	if ((instr[0] & 0x7C000000) == 0x14000000) {
		return true;
	}

	// MOVZ/MOVK sequence to synthesize addr + BR
	if ((instr[0] & 0xFFC00000) == 0xD2800000 && (instr[1] & 0xFFC00000) == 0xF2800000 && (instr[2] & 0xFFFFFC1F) == 0xD61F0000) {
		return true;
	}

	// NOP sleds
	int nops = 0;
	for (int i = 0; i < 8; ++i) {
		uint32_t word;
		if (!safe_read32(((uint32_t*)func_ptr) + i, word)) break;
		if (word == ARM64_NOP)
			nops++;
		else
			break;
	}

	if (nops >= 4) {
		return true;
	}
#endif

	return false;
}
#endif

// This function is executed every  game iteration.
void anticheat_check() {
	memory_scan_detected.clear();
#ifdef _WIN32
	std::memset(&working_set_information, 0, sizeof(working_set_information));
	working_set_information.VirtualAddress = mem_addr;
	const auto res = K32QueryWorkingSetEx((HANDLE)-1, &working_set_information, sizeof(working_set_information));
	if (res && (working_set_information.VirtualAttributes.Flags & 1) != 0) {
		memory_scan_detected.test_and_set();
		if (VirtualFree(mem_addr, 0, MEM_RELEASE) == 0) FatalAppExit(0, L"Failed to release an internal memory block"); // Should we do this, or set a flag?
		mem_addr = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}
	if (is_on_wine.test(std::memory_order_relaxed)) return;
	std::array<void*, 4> funcs {{&QueryPerformanceCounter, &timeGetTime, &GetTickCount, &GetTickCount64}};
	for (void* func: funcs)
		if (is_function_hooked(func))
			speed_hack_detected.test_and_set();
#endif
}

void anticheat_deinit() {
	#ifdef _WIN32
	if (pfn_ldr_unregister && ldr_dll_cookie) pfn_ldr_unregister(ldr_dll_cookie);
	#endif
}

#ifdef _WIN32
void handle_dll_loader_notification(ULONG reason, const PLDR_DLL_NOTIFICATION_DATA data, PVOID ctx) {
	switch (reason) {
		case LDR_DLL_NOTIFICATION_REASON_LOADED: {
			const auto name = std::wstring_view(data->Loaded.BaseDllName->Buffer);
			if (name == L"speedhack-i386.dll" || name == L"speedhack-x86_64.dll") {
				speed_hack_detected.test_and_set();
			}
			HMODULE module_handle = nullptr;
			if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(data->Loaded.DllBase), &module_handle)) {
				if (GetProcAddress(module_handle, "InitializeSpeedhack") || GetProcAddress(module_handle, "realGetTickCount") || GetProcAddress(module_handle, "realGetTickCount64") || GetProcAddress(module_handle, "realQueryPerformanceCounter") || GetProcAddress(module_handle, "speedhackversion_GetTickCount") || GetProcAddress(module_handle, "speedhackversion_GetTickCount64") || GetProcAddress(module_handle, "speedhackversion_QueryPerformanceCounter")) {
					speed_hack_detected.test_and_set();
				}
				FreeLibrary(module_handle);
			}
		} break;
		case LDR_DLL_NOTIFICATION_REASON_UNLOADED: {
			const auto name = std::wstring_view(data->Unloaded.BaseDllName->Buffer);
			if (name == L"speedhack-i386.dll" || name == L"speedhack-x86_64.dll") {
				speed_hack_detected.clear();
			}
			HMODULE module_handle = nullptr;
			if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(data->Unloaded.DllBase), &module_handle)) {
				if (GetProcAddress(module_handle, "InitializeSpeedhack") || GetProcAddress(module_handle, "realGetTickCount") || GetProcAddress(module_handle, "realGetTickCount64") || GetProcAddress(module_handle, "realQueryPerformanceCounter") || GetProcAddress(module_handle, "speedhackversion_GetTickCount") || GetProcAddress(module_handle, "speedhackversion_GetTickCount64") || GetProcAddress(module_handle, "speedhackversion_QueryPerformanceCounter")) {
					speed_hack_detected.clear();
				}
				FreeLibrary(module_handle);
			}
		} break;
	}
}
#endif

// Virtual machine detection, specifically targeting VMware and VirtualBox guests.
//
// Design goals, in priority order:
//   1. No false positives on real hardware. This is the hard constraint. In
//      particular, a *bare-metal* Windows 11 machine with Virtualization-Based
//      Security (VBS/HVCI/Credential Guard), Hyper-V or WSL2 enabled reports the
//      generic CPUID "hypervisor present" bit set and a hypervisor vendor of
//      "Microsoft Hv" even though it is NOT a virtual machine. Therefore we never
//      report a VM from generic virtualization signals alone; every trigger below
//      is tied to a VMware- or VirtualBox-specific artifact.
//   2. Detect VMware/VirtualBox as robustly as possible. A guest exposes the same
//      fingerprint through many independent channels (CPU, firmware, registry,
//      drivers, devices, services). We probe all of them, so a user who hides one
//      channel is still caught by the others. Any single positive reports a VM.
//   3. Only signals that come from *executing inside* a guest count. Signals that
//      merely prove the hypervisor software is installed (host virtual NIC MACs, the
//      host-side VMCI driver/device/service) are NOT used: a developer who runs VMs
//      for other work, but launches the game on their real desktop, must not trip.
namespace {
// Case-insensitive substring search helper.
bool icontains(const std::string& haystack, const std::string& needle) {
	if (needle.empty()) return true;
	auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(), [](char a, char b) {
		return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
	});
	return it != haystack.end();
}

#ifdef _WIN32
// Narrow a wide string to bytes for ASCII substring matching. Vendor/model/registry
// strings are ASCII, so the truncating cast is intentional (and avoids the implicit
// wchar_t->char narrowing warning from constructing a std::string from wide iterators).
std::string narrow_ascii(const std::wstring& w) {
	std::string out;
	out.reserve(w.size());
	for (wchar_t c : w) out.push_back(static_cast<char>(c & 0xFF));
	return out;
}
#endif

#ifdef NVGT_HAS_X86_CPUID
// Portable CPUID wrapper. out = {EAX, EBX, ECX, EDX}. The MSVC toolchain lacks
// GCC-style inline assembly and exposes the __cpuidex intrinsic instead; every other
// toolchain uses the inline-assembly path. The distinction is the intrinsic vs. the
// instruction, not any particular compiler.
void cpuid_raw(uint32_t leaf, uint32_t subleaf, uint32_t out[4]) {
#ifdef _MSC_VER
	int regs[4];
	__cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
	out[0] = static_cast<uint32_t>(regs[0]);
	out[1] = static_cast<uint32_t>(regs[1]);
	out[2] = static_cast<uint32_t>(regs[2]);
	out[3] = static_cast<uint32_t>(regs[3]);
#else
	__asm__ __volatile__("cpuid" : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3]) : "a"(leaf), "c"(subleaf));
#endif
}

// Read the hypervisor vendor signature from CPUID leaf 0x40000000 (12 chars laid
// out across EBX, ECX, EDX). Returns "" when no hypervisor is present.
std::string cpuid_hypervisor_vendor() {
	uint32_t regs[4];
	cpuid_raw(1, 0, regs);
	// ECX bit 31 is the "hypervisor present" hint. When clear we are on bare metal
	// and leaf 0x40000000 is not meaningful, so skip it.
	if (!(regs[2] & (1u << 31))) return std::string();
	cpuid_raw(0x40000000, 0, regs);
	char vendor[13] = {0};
	std::memcpy(vendor + 0, &regs[1], 4); // EBX
	std::memcpy(vendor + 4, &regs[2], 4); // ECX
	std::memcpy(vendor + 8, &regs[3], 4); // EDX
	return std::string(vendor);
}

// True only for VMware or VirtualBox. We deliberately ignore "Microsoft Hv"
// (Hyper-V/VBS on real Windows 11), "KVMKVMKVM", "XenVMMXenVMM", etc. so those
// do not cause false positives.
bool cpuid_is_vmware_or_vbox() {
	const std::string vendor = cpuid_hypervisor_vendor();
	return vendor == "VMwareVMware" || vendor == "VBoxVBoxVBox";
}
#else
bool cpuid_is_vmware_or_vbox() { return false; }
#endif

#ifdef _WIN32
// Run one WQL query against an already-connected namespace and test the given string
// property of every returned row for any needle (case-insensitive).
bool wmi_query_contains(IWbemServices* services, const wchar_t* wql, const wchar_t* prop, std::initializer_list<const char*> needles) {
	IEnumWbemClassObject* enumerator = nullptr;
	if (FAILED(services->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wql), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &enumerator)) || !enumerator) return false;
	bool result = false;
	IWbemClassObject* obj = nullptr;
	ULONG returned = 0;
	while (!result && enumerator->Next(WBEM_INFINITE, 1, &obj, &returned) == S_OK && returned) {
		VARIANT v;
		VariantInit(&v);
		if (SUCCEEDED(obj->Get(prop, 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR && v.bstrVal) {
			std::string s = narrow_ascii(v.bstrVal);
			for (const char* needle : needles)
				if (icontains(s, needle)) { result = true; break; }
		}
		VariantClear(&v);
		obj->Release();
	}
	enumerator->Release();
	return result;
}
#endif

// Inspect firmware/model/BIOS/baseboard/disk/video/PCI strings for VMware/VirtualBox
// vendor names. On a real machine these fields carry the physical OEM's names
// (Dell, ASUS, ...) and real PCI vendor IDs (10DE/8086/...), never "VMware",
// "innotek", VEN_15AD or VEN_80EE, so this cannot false-positive. This is the
// slowest probe (WMI/COM), so is_vm() runs it only after the cheap checks miss.
bool vm_check_hardware() {
#ifdef _WIN32
	// Connect to ROOT\CIMV2 once and reuse it for every query below. "innotek GmbH"
	// is VirtualBox's historic manufacturer; "VirtualBox"/"VBOX"/"VEN_80EE" identify
	// its devices; VMware uses "VMware"/"VMware Virtual Platform"/"VEN_15AD". We do
	// NOT match generic terms like "virtual machine", so a Hyper-V guest label (and
	// therefore a real Win11 host's Hyper-V surface) never trips this.
	bool com_initialized = false;
	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (SUCCEEDED(hr)) com_initialized = true;
	else if (hr != RPC_E_CHANGED_MODE) return false; // COM unavailable; assume not a VM.
	bool result = false;
	IWbemLocator* locator = nullptr;
	IWbemServices* services = nullptr;
	if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<void**>(&locator))) && locator) {
		if (SUCCEEDED(locator->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services)) && services) {
			CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
			result = wmi_query_contains(services, L"SELECT Model FROM Win32_ComputerSystem", L"Model", {"vmware", "virtualbox", "vbox"})
				|| wmi_query_contains(services, L"SELECT Manufacturer FROM Win32_ComputerSystem", L"Manufacturer", {"vmware", "innotek", "virtualbox"})
				|| wmi_query_contains(services, L"SELECT SMBIOSBIOSVersion FROM Win32_BIOS", L"SMBIOSBIOSVersion", {"vmware", "virtualbox", "vbox"})
				|| wmi_query_contains(services, L"SELECT Manufacturer FROM Win32_BIOS", L"Manufacturer", {"vmware", "innotek", "virtualbox"})
				|| wmi_query_contains(services, L"SELECT SerialNumber FROM Win32_BIOS", L"SerialNumber", {"vmware-"})
				|| wmi_query_contains(services, L"SELECT Product FROM Win32_BaseBoard", L"Product", {"vmware", "virtualbox", "vbox"})
				|| wmi_query_contains(services, L"SELECT Name FROM Win32_VideoController", L"Name", {"vmware", "virtualbox", "vbox"})
				// The emulated display adapter is the hardest signal for a hardened VM to hide:
				// its PCI vendor ID (VMware SVGA = VEN_15AD, VirtualBox = VEN_80EE) is baked into
				// the virtual hardware and survives .vmx SMBIOS/CPUID/MAC spoofing and uninstalling
				// the guest tools. Match the vendor ID directly, not the driver-provided Name, since
				// with no tools installed the adapter shows a generic name but keeps its PCI ID.
				|| wmi_query_contains(services, L"SELECT PNPDeviceID FROM Win32_VideoController", L"PNPDeviceID", {"ven_15ad", "ven_80ee"})
				|| wmi_query_contains(services, L"SELECT Model, PNPDeviceID FROM Win32_DiskDrive", L"Model", {"vmware", "virtualbox", "vbox"})
				|| wmi_query_contains(services, L"SELECT PNPDeviceID FROM Win32_DiskDrive", L"PNPDeviceID", {"ven_vmware", "ven_80ee", "vbox"})
				|| wmi_query_contains(services, L"SELECT DeviceID FROM Win32_PnPEntity WHERE DeviceID LIKE '%VEN_15AD%' OR DeviceID LIKE '%VEN_80EE%'", L"DeviceID", {"ven_15ad", "ven_80ee"});
			services->Release();
		}
		locator->Release();
	}
	if (com_initialized) CoUninitialize();
	return result;
#elif defined(__APPLE__)
	char buf[256] = {0};
	size_t len = sizeof(buf) - 1;
	if (sysctlbyname("hw.model", buf, &len, nullptr, 0) != 0) return false;
	std::string model(buf);
	return icontains(model, "VMware") || icontains(model, "VirtualBox");
#else // Linux
	// DMI/SMBIOS fields exposed by the kernel. These carry the physical OEM's names
	// on real hardware, so a VMware/VirtualBox string here is definitive.
	const char* dmi_files[] = {
		"/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/board_vendor", "/sys/class/dmi/id/bios_vendor",
		"/sys/class/dmi/id/product_serial", "/sys/class/dmi/id/board_name",
	};
	for (const char* path : dmi_files) {
		std::ifstream f(path);
		if (!f) continue;
		std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		if (icontains(content, "vmware") || icontains(content, "virtualbox") || icontains(content, "innotek") || icontains(content, "vbox")) return true;
	}
	// systemd-detect-virt names the specific technology; restrict to our targets.
	FILE* pipe = popen("systemd-detect-virt 2>/dev/null", "r");
	if (pipe) {
		std::string output;
		char buf[128];
		while (fgets(buf, sizeof(buf), pipe)) output += buf;
		int status = pclose(pipe);
		output.erase(std::remove_if(output.begin(), output.end(), [](unsigned char c) { return std::isspace(c); }), output.end());
		if (status == 0 && (output == "vmware" || output == "oracle")) return true;
	}
	return false;
#endif
}

#ifdef _WIN32
// Read the raw SMBIOS (DMI) firmware table and scan its string data for VMware/VirtualBox
// vendor strings. This bypasses WMI entirely (harder to spoof from user space than the
// model string) and works even when the guest tools have been uninstalled.
//
// CRITICAL: we scan ONLY the null-terminated string set of each SMBIOS structure, never the
// raw blob. Each structure is a fixed-size *binary* formatted area (which includes the 16-byte
// System-Information UUID and other essentially-random bytes) followed by its string pool. A
// naive substring search over the whole blob false-positives on real hardware: the 4-byte
// needle "vbox" (case-insensitive) can appear by chance inside that binary data -- most easily
// the random UUID -- flagging a physical machine that has never run VirtualBox. Parsing out the
// string pool eliminates the coincidence while still catching real guests, which write "VMware"/
// "VirtualBox"/"innotek" into DMI string fields (BIOS vendor, system/baseboard manufacturer, ...).
bool vm_check_smbios() {
	const DWORD signature = 'RSMB'; // Raw SMBIOS firmware table provider.
	UINT size = GetSystemFirmwareTable(signature, 0, nullptr, 0);
	if (!size) return false;
	std::string raw(size, '\0');
	if (GetSystemFirmwareTable(signature, 0, raw.data(), size) != size) return false;
	// RawSMBIOSData header: 8 bytes (calling method, version bytes, DmiRevision) then a
	// little-endian DWORD Length, then the DMI structures themselves.
	if (raw.size() < 8) return false;
	const uint8_t* p = reinterpret_cast<const uint8_t*>(raw.data());
	const uint32_t table_len = static_cast<uint32_t>(p[4]) | (static_cast<uint32_t>(p[5]) << 8) | (static_cast<uint32_t>(p[6]) << 16) | (static_cast<uint32_t>(p[7]) << 24);
	size_t end = 8 + static_cast<size_t>(table_len);
	if (end > raw.size()) end = raw.size();
	// Walk each structure: byte 0 = type, byte 1 = length of the formatted (binary) area
	// (including the 4-byte header), bytes 2-3 = handle. The string set follows the formatted
	// area and runs until a double-NUL. We copy only the string-set bytes into `strings`.
	std::string strings;
	for (size_t off = 8; off + 4 <= end; ) {
		const uint8_t type = p[off];
		const uint8_t formatted_len = p[off + 1];
		if (formatted_len < 4) break; // malformed: the formatted area must cover its own header.
		size_t s = off + formatted_len; // skip the binary formatted area (UUID etc.).
		if (s > end) break;
		while (s < end) {
			if (p[s] == 0) {
				if (s + 1 >= end || p[s + 1] == 0) { s += 2; break; } // double-NUL ends the structure.
				strings.push_back(' '); // single NUL separates two strings.
				++s;
			} else {
				strings.push_back(static_cast<char>(p[s]));
				++s;
			}
		}
		if (type == 127) break; // end-of-table structure.
		off = s;
	}
	return icontains(strings, "vmware") || icontains(strings, "virtualbox") || icontains(strings, "vbox") || icontains(strings, "innotek");
}

// True if the registry value (REG_SZ / REG_MULTI_SZ) under (root, subkey, value)
// contains any needle. Reads via both 64-bit and 32-bit views.
bool reg_value_contains(HKEY root, const wchar_t* subkey, const wchar_t* value, std::initializer_list<const char*> needles) {
	for (REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
		HKEY key;
		if (RegOpenKeyExW(root, subkey, 0, KEY_READ | view, &key) != ERROR_SUCCESS) continue;
		BYTE buf[1024] = {0};
		DWORD len = sizeof(buf), type = 0;
		LONG rc = RegQueryValueExW(key, value, nullptr, &type, buf, &len);
		RegCloseKey(key);
		if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_MULTI_SZ)) continue;
		std::wstring w(reinterpret_cast<wchar_t*>(buf), len / sizeof(wchar_t));
		std::string s = narrow_ascii(w);
		for (const char* needle : needles)
			if (icontains(s, needle)) return true;
	}
	return false;
}

// True if the named kernel driver / service is not merely REGISTERED but currently RUNNING.
//
// This distinction is the entire point. A key under SYSTEM\CurrentControlSet\Services proves
// only that VMware/VirtualBox software touched this machine at some point: such keys survive
// uninstalls, they come along when a Windows image that was prepared inside a VM is deployed to
// physical hardware, and migration tools are documented to leave them behind (virt-v2v, for one,
// does not remove the vmrawdsk/vmmemctl driver registrations when converting a VM *away* from
// VMware). A genuine guest, by contrast, has the driver loaded -- the guest tools are what make
// the VM usable at all. Asking the SCM for the live state converts an install-time record into a
// runtime fact, which is what we actually want to know.
bool service_is_running(const wchar_t* name) {
	SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!scm) return false;
	bool running = false;
	if (SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS)) {
		SERVICE_STATUS st = {};
		if (QueryServiceStatus(svc, &st))
			running = st.dwCurrentState == SERVICE_RUNNING || st.dwCurrentState == SERVICE_START_PENDING;
		CloseServiceHandle(svc);
	}
	CloseServiceHandle(scm);
	return running;
}

// True if the registry key itself exists (presence is the signal).
bool reg_key_exists(HKEY root, const wchar_t* subkey) {
	for (REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
		HKEY key;
		if (RegOpenKeyExW(root, subkey, 0, KEY_READ | view, &key) == ERROR_SUCCESS) {
			RegCloseKey(key);
			return true;
		}
	}
	return false;
}

// Registry artifacts unique to VMware or VirtualBox guests.
bool vm_check_registry() {
	// The registry holds two very different classes of evidence, and conflating them is what
	// produced this function's false positives:
	//
	//  * The HARDWARE hive is VOLATILE -- Windows discards it on shutdown and rebuilds it every
	//    boot from the firmware tables and PnP enumeration actually present on the machine.
	//    Nothing there can be stale, so a VirtualBox ACPI OEM id or a "VMware" BIOS string found
	//    here really does mean we are executing inside a guest.
	//  * SYSTEM\...\Services and SOFTWARE\... are PERSISTENT installation records. They attest
	//    that VMware/VirtualBox software once touched this box -- nothing more. They outlive
	//    uninstalls, they ride along when a Windows image prepared inside a VM is deployed onto
	//    physical hardware, and V2P/V2V converters are known to leave the guest driver
	//    registrations behind. Those entries are therefore only believed while the driver is
	//    actually RUNNING, which no amount of leftover registry state can fake.

	// --- Firmware and PnP evidence (volatile hive: current by construction). ---
	// VirtualBox stamps "VBOX__" as the OEM id of the ACPI tables it synthesises for the guest.
	const wchar_t* acpi_keys[] = {
		L"HARDWARE\\ACPI\\DSDT\\VBOX__",
		L"HARDWARE\\ACPI\\FADT\\VBOX__",
		L"HARDWARE\\ACPI\\RSDT\\VBOX__",
	};
	for (const wchar_t* k : acpi_keys)
		if (reg_key_exists(HKEY_LOCAL_MACHINE, k)) return true;
	// BIOS/SCSI identifier strings recorded by the firmware.
	if (reg_value_contains(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", L"SystemBiosVersion", {"vbox", "vmware", "virtualbox"})) return true;
	if (reg_value_contains(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", L"VideoBiosVersion", {"virtualbox", "vmware"})) return true;
	if (reg_value_contains(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer", {"vmware", "innotek", "virtualbox"})) return true;
	if (reg_value_contains(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName", {"vmware", "virtualbox", "vbox"})) return true;
	// The SCSI controller identifier recorded by the firmware carries the virtual
	// disk vendor. Both hypervisors expose their disks on port 0.
	if (reg_value_contains(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", L"Identifier", {"vmware", "vbox", "virtualbox"})) return true;

	// --- Guest-tool drivers, believed only while loaded (see service_is_running). ---
	const wchar_t* guest_services[] = {
		// VirtualBox Guest Additions -- installed inside the guest only.
		L"VBoxGuest", L"VBoxMouse", L"VBoxService", L"VBoxSF", L"VBoxVideo",
		// VMware Tools. Deliberately absent from this list:
		//   vmci -- VMware Workstation registers it on the HOST, so it says nothing about us.
		//   vmrawdsk -- the "VMware Raw Disk Helper Driver". It is a stock VMware Tools component
		//     shipped to every modern Windows guest whether or not raw disks are used, and it is
		//     a documented leftover of migrating a machine *away* from VMware (virt-v2v does not
		//     remove it). It is not in Check Point's VM-detection registry catalogue either. This
		//     is the entry that misclassified a real player's physical machine, and even gated on
		//     "running" it buys nothing: an actual VMware guest trips the backdoor port, CPUID,
		//     SMBIOS and GPU-vendor probes regardless.
		L"vmhgfs", L"vmmouse", L"vmusbmouse", L"vmvss", L"vmscsi", L"vmxnet", L"VMTools",
	};
	for (const wchar_t* s : guest_services)
		if (service_is_running(s)) return true;
	// Three former checks were dropped outright rather than gated, because there is no runtime
	// state behind them to gate on:
	//   SOFTWARE\Oracle\VirtualBox Guest Additions and SOFTWARE\VMware, Inc.\VMware Tools are pure
	//     product-install records, so they persist verbatim after an uninstall or a V2P image.
	//   SYSTEM\...\Services\Disk\Enum lists disk device instances including non-present ones, and
	//     mounting a .vmdk on a physical machine (a normal thing to do with VMware Workstation
	//     installed) leaves a "VMware" instance path there forever.
	// The Scsi Identifier check above covers the same ground from the volatile hive.
	return false;
}
#endif

// Guest device objects whose driver can only bind to EMULATED HARDWARE.
//
// This probe used to test for guest-tool install directories, driver/DLL files and processes
// as well. Every one of those was removed, because they answer the wrong question. There are
// two separable questions here:
//
//   Q1 "is this machine virtual?"      -- a property of the hardware and firmware.
//   Q2 "is guest-tool software here?"  -- a property of what someone installed.
//
// Installing VMware Tools or the Guest Additions on a physical PC -- deliberately, by accident,
// or by deploying a Windows image that was originally prepared inside a VM -- answers Q2 yes on
// a machine where Q1 is emphatically no. That is not hypothetical: it misclassified a real
// player, whose PC carried the whole VMware Tools install (directory, drivers and service key)
// without ever having been a guest.
//
// A Q2 signal can only ever change is_vm()'s verdict when every Q1 probe has already missed,
// i.e. against a deliberately hardened guest -- and step one of hardening a guest is removing
// the guest tools. So in the single scenario where a Q2 probe could earn its place, it finds
// nothing. It is dead weight by construction, and its false-positive cost is real.
//
// What survives is the narrow case that is genuinely Q1: a device node whose driver is bound by
// PnP to a virtual PCI device. VBoxGuest.sys attaches to the VirtualBox Guest Device
// (PCI VEN_80EE&DEV_CAFE); with no such device on the bus the driver cannot start and the node
// cannot be opened, no matter how thoroughly the Guest Additions are installed. Shared-folder
// redirectors (\\.\HGFS, \\.\VBoxMiniRdrDN) and tray-process pipes (\\.\pipe\VBoxTrayIPC) are
// NOT bound to emulated hardware and so are excluded -- they load wherever the software does.
bool vm_check_guest_devices() {
#ifdef _WIN32
	const wchar_t* devices[] = {
		L"\\\\.\\VBoxGuest",
		// NOTE: \\.\vmci is deliberately NOT listed -- the VMware VMCI Bus Device is present
		// on a VMware Workstation HOST too, so opening it flags real machines. VMware guests
		// are covered by the backdoor port, CPUID, SMBIOS and GPU-vendor probes instead.
	};
	for (const wchar_t* dev : devices) {
		HANDLE h = CreateFileW(dev, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
		if (h != INVALID_HANDLE_VALUE) {
			CloseHandle(h);
			return true;
		}
		if (GetLastError() == ERROR_ACCESS_DENIED) return true; // Exists but locked -> present.
	}
	return false;
#elif defined(__APPLE__)
	// Nothing here is hardware-bound: VMware Fusion guest tools install to a fixed path that
	// says nothing about the current machine. hw.model (vm_check_hardware) and ioreg
	// (vm_check_pci) identify real Mac guests from the hardware itself.
	return false;
#else // Linux
	// Only the vboxguest character devices, created by the kernel module that binds to the
	// emulated VirtualBox Guest PCI device. The Guest Additions / VMware Tools *binaries*
	// (/usr/bin/VBoxClient, /usr/bin/vmtoolsd, ...) are deliberately not tested: they are
	// installed software, not hardware. /dev/vmci is likewise omitted -- VMware Workstation's
	// vmw_vmci module creates it on the HOST.
	const char* paths[] = {"/dev/vboxguest", "/dev/vboxuser"};
	for (const char* p : paths)
		if (access(p, F_OK) == 0) return true;
	return false;
#endif
}

// NOTE: A NIC-MAC OUI probe used to live here but was removed: installing VMware or
// VirtualBox on a *host* creates persistent host-side virtual adapters (VMware VMnet1/
// VMnet8 at 00:50:56:C0:xx, VirtualBox Host-Only at 08:00:27/0A:00:27) whose MACs carry
// the very OUIs it matched. A developer who merely has either product installed -- but
// is NOT running the game in a VM -- would be misclassified as a guest. MAC OUI cannot
// distinguish "host with VM software installed" from "actual guest", so the whole check
// is unsalvageable; the firmware/CPUID/ACPI probes below detect real guests reliably.

// The VMware "backdoor" I/O request: magic 'VMXh' (0x564D5868) in EAX, command
// GETVERSION (0x0A) in ECX, port 'VX' (0x5658) in DX. On a VMware guest the IN
// instruction is intercepted and returns the magic back in EBX; on real hardware the
// privileged IN raises #GP. The port IN and register setup are implemented in the
// hand-written assembly stub src/vmware_backdoor.asm (x64 Windows only), because the
// backdoor protocol -- preloading EBX/ECX and reading EBX back -- cannot be expressed
// with the port-I/O intrinsics available on x64, and #GP recovery here relies on
// Windows SEH. VMware on other platforms is still caught by the CPUID "VMwareVMware"
// vendor, SMBIOS/DMI, the \\.\HGFS device, registry and guest services.
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
extern "C" uint32_t vmware_backdoor_probe(void);

// VMware-specific and near-zero false positive: a real machine (including a Windows 11
// host with Hyper-V/VBS enabled) cannot answer the backdoor and instead faults on the
// privileged IN, which the SEH wrapper swallows.
bool vm_check_vmware_backdoor() {
	__try {
		return vmware_backdoor_probe() == 0x564D5868;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}
#elif !defined(_WIN32) && (defined(__i386__) || defined(__x86_64__))
// POSIX (Linux / Intel macOS) equivalent of the backdoor probe. There is no SEH, so
// the privileged IN's fault (delivered as SIGSEGV, or SIGILL/SIGBUS on some kernels)
// is recovered with a scoped signal handler + siglongjmp. We install the handlers only
// for the microsecond-long probe and restore the previous ones immediately afterward,
// so the engine's own crash handling is never permanently displaced. (Not re-entrant:
// is_vm() is expected to be called from a single thread.)
static sigjmp_buf vm_bd_jmp;
static void vm_bd_signal(int) { siglongjmp(vm_bd_jmp, 1); }

bool vm_check_vmware_backdoor() {
	struct sigaction sa {}, old_segv {}, old_ill {}, old_bus {};
	sa.sa_handler = vm_bd_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGSEGV, &sa, &old_segv);
	sigaction(SIGILL, &sa, &old_ill);
	sigaction(SIGBUS, &sa, &old_bus);
	bool result = false;
	if (sigsetjmp(vm_bd_jmp, 1) == 0) {
		uint32_t eax = 0x564D5868, ebx = 0, ecx = 0x0A, edx = 0x5658;
		__asm__ __volatile__("inl %%dx, %%eax" : "+a"(eax), "+b"(ebx), "+c"(ecx), "+d"(edx));
		result = (ebx == 0x564D5868); // faults on bare metal -> handler longjmps, result stays false
	}
	sigaction(SIGSEGV, &old_segv, nullptr);
	sigaction(SIGILL, &old_ill, nullptr);
	sigaction(SIGBUS, &old_bus, nullptr);
	return result;
}
#else
bool vm_check_vmware_backdoor() { return false; }
#endif

#ifdef _WIN32
// Enumerate graphics adapters through DXGI and match the emulated GPU by its PCI
// vendor ID (VMware SVGA = 0x15AD, VirtualBox = 0x80EE) or adapter description. This
// is the single hardest signal for a hardened VM to hide: the virtual GPU is present
// even with no guest tools and its PCI vendor ID cannot be rewritten by any .vmx
// setting. DXGI reads the adapter straight from the graphics stack -- a different code
// path from the WMI/PnP query in vm_check_hardware -- so an attacker must hook both to
// conceal it. CreateDXGIFactory is loaded dynamically to avoid a static dxgi.lib
// dependency; the IID comes from the already-linked dxguid.lib.
bool vm_check_dxgi() {
	HMODULE dxgi = LoadLibraryW(L"dxgi.dll");
	if (!dxgi) return false;
	using PFN_CreateDXGIFactory = HRESULT(WINAPI*)(REFIID, void**);
	auto create = reinterpret_cast<PFN_CreateDXGIFactory>(GetProcAddress(dxgi, "CreateDXGIFactory"));
	bool found = false;
	IDXGIFactory* factory = nullptr;
	if (create && SUCCEEDED(create(__uuidof(IDXGIFactory), reinterpret_cast<void**>(&factory))) && factory) {
		IDXGIAdapter* adapter = nullptr;
		for (UINT i = 0; !found && factory->EnumAdapters(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
			DXGI_ADAPTER_DESC desc;
			if (SUCCEEDED(adapter->GetDesc(&desc))) {
				if (desc.VendorId == 0x15AD || desc.VendorId == 0x80EE) found = true;
				else {
					std::string d = narrow_ascii(desc.Description);
					if (icontains(d, "vmware") || icontains(d, "virtualbox") || icontains(d, "vbox")) found = true;
				}
			}
			adapter->Release();
		}
		factory->Release();
	}
	FreeLibrary(dxgi);
	return found;
}
#endif

// NOTE: a running-process scan for the guest-tool daemons (vmtoolsd.exe, VBoxService, ...)
// used to live here. It was removed for the same reason as the guest-tool file checks above:
// it answers "is guest-tool software installed and running here?", not "is this machine a
// virtual machine?". Those daemons start on any PC where the tools were installed -- including
// a physical one imaged from a VM template -- and conversely they are the first thing removed
// from a guest that is being hardened against detection, so the probe both misfired on real
// players and was blind exactly when it would have mattered. Genuine guests are identified
// from the hardware itself by the CPUID, backdoor-port, SMBIOS, ACPI and GPU-vendor probes.

// PCI / GPU vendor probe for POSIX (the cross-platform counterpart of vm_check_dxgi).
// The emulated VMware SVGA (PCI vendor 0x15AD) or VirtualBox devices (0x80EE) are the
// hardest signal for a hardened guest to hide -- present even with no guest tools and
// unforgeable by any .vmx setting. On Windows this is covered by DXGI + WMI PnP.
bool vm_check_pci() {
#if defined(_WIN32)
	return false; // handled by vm_check_dxgi() + Win32_PnPEntity in vm_check_hardware().
#elif defined(__APPLE__)
	// No sysfs on macOS; query the IO registry for the virtual GPU / devices.
	FILE* pipe = popen("ioreg -l 2>/dev/null", "r");
	if (!pipe) return false;
	std::string out;
	char buf[512];
	bool found = false;
	while (!found && fgets(buf, sizeof(buf), pipe)) {
		std::string line(buf);
		if (icontains(line, "vmware") || icontains(line, "virtualbox") || icontains(line, "0x15ad") || icontains(line, "0x80ee")) found = true;
	}
	pclose(pipe);
	return found;
#else
	// Linux: every PCI device exposes its vendor id at /sys/bus/pci/devices/*/vendor.
	DIR* dir = opendir("/sys/bus/pci/devices");
	if (!dir) return false;
	bool found = false;
	for (struct dirent* ent = readdir(dir); ent && !found; ent = readdir(dir)) {
		if (ent->d_name[0] == '.') continue;
		std::ifstream f(std::string("/sys/bus/pci/devices/") + ent->d_name + "/vendor");
		std::string v;
		if (!f || !std::getline(f, v)) continue;
		// Content is like "0x15ad".
		if (icontains(v, "15ad") || icontains(v, "80ee")) found = true;
	}
	closedir(dir);
	return found;
#endif
}

// The Windows Sandbox user profile marker. Windows Sandbox is a Hyper-V-backed
// disposable VM; this is a specific, non-generic artifact that never appears on a
// normal desktop.
bool vm_check_sandbox_files() {
#ifdef _WIN32
	wchar_t profile[MAX_PATH * 2];
	if (ExpandEnvironmentStringsW(L"%userprofile%", profile, MAX_PATH * 2)) {
		std::wstring p(profile);
		if (p.find(L"WDAGUtilityAccount") != std::wstring::npos) return true;
	}
	return false;
#else
	return false; // Windows-only check.
#endif
}
} // namespace

bool is_vm() {
	// True if ANY VMware/VirtualBox-specific signal fires. Each probe is a distinct
	// channel, so hiding one (e.g. masking the CPUID vendor) still leaves the others.
	//
	// Every probe here answers one question and one only: "is the hardware this process is
	// executing on virtual?" It is deliberately blind to the separate question "is VMware or
	// VirtualBox software installed on this machine?", because the two are independent. A
	// physical PC can carry a complete VMware Tools installation -- someone installed it, or
	// its Windows image was prepared inside a VM and then deployed to real hardware -- and
	// answering the second question got exactly such a player misclassified. Probes that read
	// installed files, service registrations or running helper processes were therefore removed;
	// what remains reads CPUID, the VMware backdoor port, firmware (SMBIOS/ACPI/DMI), emulated
	// PCI/GPU vendor ids and hardware-bound device nodes. None of those can be produced by
	// installing software, so none fires on bare metal -- including a Windows 11 host running
	// Hyper-V/VBS/WSL2, or one with VMware Workstation and VirtualBox both installed.
	//
	// Ordered cheapest-first and short-circuiting: the CPUID/firmware/registry/device
	// probes are near-instant, so the expensive WMI query only runs when everything
	// else has already missed.
	if (cpuid_is_vmware_or_vbox()) return true;
	if (vm_check_vmware_backdoor()) return true;
#ifdef _WIN32
	if (vm_check_smbios()) return true;
	if (vm_check_registry()) return true;
#endif
	if (vm_check_guest_devices()) return true;
	if (vm_check_pci()) return true; // POSIX emulated-GPU/PCI residual (VEN_15AD/80EE); survives hardening.
#ifdef _WIN32
	if (vm_check_dxgi()) return true; // Windows GPU by PCI vendor id; survives VM hardening.
#endif
	if (vm_check_sandbox_files()) return true;
	if (vm_check_hardware()) return true; // Slowest (WMI/COM); last resort.
	return false;
}

void register_anticheat(asIScriptEngine* engine) {
#ifdef _WIN32
	mem_addr = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	HMODULE ntdll_handle = GetModuleHandle(L"ntdll.dll");
	assert(ntdll_handle != INVALID_HANDLE_VALUE || ntdll_handle != NULL);
	// If this fails, consider it a fatal exit condition, because ntdll.dll should (always) be loaded
	if (ntdll_handle == INVALID_HANDLE_VALUE || ntdll_handle == NULL) FatalAppExit(0, L"NtDll.dll was not found in the module list!");
	pfn_ldr_register = reinterpret_cast<PFN_LdrRegisterDllNotification>(GetProcAddress(ntdll_handle, "LdrRegisterDllNotification"));
	pfn_ldr_unregister = reinterpret_cast<PFN_LdrUnregisterDllNotification>(GetProcAddress(ntdll_handle, "LdrUnregisterDllNotification"));
	assert(pfn_ldr_register != NULL);
	assert(pfn_ldr_unregister != NULL);
	if (pfn_ldr_register) pfn_ldr_register(0, &handle_dll_loader_notification, nullptr, &ldr_dll_cookie);
	if (GetProcAddress(ntdll_handle, "wine_get_version") != nullptr)
		is_on_wine.test_and_set();
#endif
	engine->RegisterGlobalProperty("const atomic_flag speed_hack_detected", (void*)&speed_hack_detected);
	engine->RegisterGlobalProperty("const atomic_flag memory_scan_detected", (void*)&memory_scan_detected);
	engine->RegisterGlobalFunction("bool is_vm()", asFUNCTION(is_vm), asCALL_CDECL);
}
