#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <memory>
#include <regex>
#include <array>
#include <fstream>
#include <filesystem>
#include <sstream>
#include "xorstr.hpp"

#define NtCurrentProcess ((HANDLE)-1)

void DebugLog(const char* c_szLogData)
{
	OutputDebugStringA(c_szLogData);
}

void __DebugLogf(const char* c_szFormat, ...)
{
	char szBuffer[16000];

	va_list vaArgList;
	va_start(vaArgList, c_szFormat);
	vsprintf_s(szBuffer, c_szFormat, vaArgList);
	va_end(vaArgList);

	DebugLog(szBuffer);
}

#ifdef _DEBUG
#define DebugLogf(log, ...)	__DebugLogf(log, __VA_ARGS__);
#else
#define DebugLogf(log, ...)
#endif

typedef struct _MEM_PATTERN
{
	_MEM_PATTERN(const std::string& mask, const void* buffer) :
		_pattern(mask.size()), _buffer(buffer), _mask(mask)
	{
		for (std::size_t i = 0; i < _pattern.size(); ++i)
		{
			_pattern[i].first = mask[i];
			_pattern[i].second = reinterpret_cast<const uint8_t*>(buffer)[i];
		}
	}
	~_MEM_PATTERN() = default;

	size_t GetLength() const { return _pattern.size(); };

	char GetMask(size_t index) const { return _pattern.at(index).first; };
	const char* GetMask() const { return _mask.c_str(); };

	uint8_t GetByte(size_t index) const { return _pattern.at(index).second; };
	const void* GetBytes() const { return _buffer; };

	std::vector <std::pair <char, uint8_t> > _pattern;
	const void* _buffer;
	std::string _mask;
} SPattern, * PPattern;

void replaceAll(std::string& s, const std::string& search, const std::string& replace)
{
	for (size_t pos = 0; ; pos += replace.length())
	{
		pos = s.find(search, pos);
		if (pos == std::string::npos)
			break;

		s.erase(pos, search.length());
		s.insert(pos, replace);
	}
}

std::vector <std::string> DirectoryList(const std::string& input, const std::string& delim = "\\")
{
	auto list = std::vector<std::string>();

	size_t start = 0;
	auto end = input.find(delim);
	while (end != std::string::npos)
	{
		list.emplace_back(input.substr(0, end));
		start = end + delim.length();
		end = input.find(delim, start);
	}

	return list;
}

inline bool ReadMemory(void* lpAddress, void* lpBuffer, size_t cbSize)
{
	auto dwReadByteCount = 0UL;
	auto dwOldProtect = 0UL;
	__try
	{
		if (VirtualProtectEx(NtCurrentProcess, lpAddress, cbSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			if (!ReadProcessMemory(NtCurrentProcess, lpAddress, lpBuffer, cbSize, &dwReadByteCount))
			{
				DebugLogf("ReadProcessMemory fail! Error: %u", GetLastError());
				dwReadByteCount = 0;
			}

			VirtualProtectEx(NtCurrentProcess, lpAddress, cbSize, dwOldProtect, &dwOldProtect);
		}
		else
		{
			DebugLogf("VirtualProtectEx(pre) fail! Error: %u", GetLastError());
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DebugLogf("ReadMemory exception handled");
	}

	return (dwReadByteCount && dwReadByteCount == cbSize);
}

inline uintptr_t FindPattern(uint8_t* address, size_t size, const std::shared_ptr <SPattern>& pattern)
{
	auto vBuffer = std::vector <uint8_t>(size);

	if (!ReadMemory(address, &vBuffer[0], size))
	{
		DebugLogf("FindPattern Read fail. %p - %u(real) - %u(read) | %p\n", address, size, vBuffer.size(), pattern->GetBytes());
		return 0;
	}

	uintptr_t dwResult = 0;
	for (size_t i = 0; i + pattern->GetLength() < vBuffer.size(); ++i)
	{
		auto bFound = true;
		for (size_t j = 0; j < pattern->GetLength() && bFound; ++j)
		{
			if (pattern->GetMask(j) == '?')
				continue;
			if (pattern->GetByte(j) == vBuffer[i + j])
				continue;

			bFound = false;
		}

		if (bFound)
		{
			dwResult = reinterpret_cast<uintptr_t>(address + i);
			break;
		}
	}

	return dwResult;
}

uintptr_t SearchPattern(std::shared_ptr <SPattern> pattern)
{
	auto pTargetAddr = uintptr_t(0);
	auto dwBaseAddress = 0UL;
	auto mbi = MEMORY_BASIC_INFORMATION{ 0 };

	auto bufferSize = 0ULL;
	while (bufferSize = VirtualQueryEx(NtCurrentProcess, reinterpret_cast<LPCVOID>(dwBaseAddress), &mbi, sizeof(mbi)))
	{
		// DebugLogf("SearchPattern - Current region: %p-%u", mbi.BaseAddress, mbi.RegionSize);

		if (reinterpret_cast<uint32_t>(mbi.BaseAddress) < 0x400000)
			goto ContinueLoop;

		if (mbi.State != MEM_COMMIT)
			goto ContinueLoop;
		if (mbi.Protect == PAGE_NOACCESS)
			goto ContinueLoop;
		if (mbi.Protect & PAGE_GUARD)
			goto ContinueLoop;

		pTargetAddr = FindPattern(reinterpret_cast<uint8_t*>(mbi.BaseAddress), mbi.RegionSize, pattern);
		if (pTargetAddr)
			break;

	ContinueLoop:
		dwBaseAddress += mbi.RegionSize;
	}

	return pTargetAddr;
}

uintptr_t SearchFunction(uintptr_t pRefAddr)
{
	DebugLogf("SearchFunction ref: %p", pRefAddr);

	auto pTarget = uintptr_t(0);
	auto dwBaseAddress = 0UL;

	auto pStart = uintptr_t(0);
	auto pEnd = uintptr_t(0);

	auto bufferSize = 0UL;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	while (bufferSize = VirtualQueryEx(NtCurrentProcess, reinterpret_cast<LPCVOID>(dwBaseAddress), &mbi, sizeof(mbi)))
	{
		if (reinterpret_cast<uintptr_t>(mbi.BaseAddress) < 0x400000)
			goto ContinueLoop;

		DebugLogf("current page: %p/%p %u -- %p %p",
			mbi.BaseAddress, reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize, mbi.RegionSize, mbi.State, mbi.Protect);

		if (mbi.State != MEM_COMMIT)
			goto ContinueLoop;

		switch (mbi.Protect)
		{
		case PAGE_READONLY:
		case PAGE_READWRITE:
		case PAGE_EXECUTE_READ:
		case PAGE_EXECUTE_READWRITE:
		case PAGE_EXECUTE_WRITECOPY:
			break;
		default:
			goto ContinueLoop;
		}

		DebugLogf("processing...");
		pStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
		pEnd = (reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize) - sizeof(uintptr_t);

		while (*(uint32_t*)pStart != pRefAddr && pStart < pEnd)
		{
			// DebugLogf("cur: %p", dwStart);
			pStart++;
		}

		if (pStart != pEnd)
		{
			pTarget = pStart;
			DebugLogf("Func found! Target: %p", pTarget);
			break;
		}

	ContinueLoop:
		dwBaseAddress += mbi.RegionSize;
	}

	DebugLogf("Found: %p", pTarget);
	return pTarget;
}

#define Relative2Absolute(pBase, dwOffset, dwLength) (PVOID)((SIZE_T)pBase + (*(PLONG)((PBYTE)pBase + dwOffset)) + dwLength)

enum EArgTypes : uint8_t
{
	ARG_TYPE_NULL,
	ARG_TYPE_3_ARG,
	ARG_TYPE_4_ARG,
	ARG_TYPE_5_ARG
};
enum ECCTypes : uint8_t
{
	CC_TYPE_NULL,
	CC_TYPE_THISCALL,
	CC_TYPE_STDCALL
};

typedef void* (__cdecl* TEterClassFindFunc)();
typedef void* (__thiscall* TMappedFileLoad)(void* This);
typedef bool(__thiscall* TEterPackManagerGet_3_thiscall)(void* This, void* rMappedFile, const char* c_szFileName, LPVOID* data);
typedef bool(__thiscall* TEterPackManagerGet_4_thiscall)(void* This, void* rMappedFile, const char* c_szFileName, LPVOID* data, int a4_unk);
typedef bool(__thiscall* TEterPackManagerGet_5_thiscall)(void* This, void* rMappedFile, const char* c_szFileName, LPVOID* data, const char* c_szFuncName, char a5_unk);
typedef bool(__stdcall* TEterPackManagerGet_3_stdcall)(void* rMappedFile, const char* c_szFileName, LPVOID* data);
typedef bool(__stdcall* TEterPackManagerGet_4_stdcall)(void* rMappedFile, const char* c_szFileName, LPVOID* data, int a4_unk);
typedef bool(__stdcall* TEterPackManagerGet_5_stdcall)(void* rMappedFile, const char* c_szFileName, LPVOID* data, const char* c_szFuncName, char a5_unk);

static uintptr_t gs_MappedFileSizeOffset = 0;
static uintptr_t gs_MappedFileLoadPtr = 0;
static uintptr_t gs_EterPackManagerClassPtr = 0;
static uintptr_t gs_EterPackManagerGetAddress = 0;

static bool gs_bMappedInit = false;
static std::vector <uint8_t> gs_vMappedFileBuffer(0x2000);

static uint8_t gs_nArgType = ARG_TYPE_NULL;
static uint8_t gs_nCallConvType = CC_TYPE_NULL;

bool packGet(const std::string& stInputFileName, std::string stOutputFileName)
{
	auto bRet = false;

	DebugLogf("In: %s Out: %s", stInputFileName.c_str(), stOutputFileName.c_str());

	if (!gs_bMappedInit)
	{
		reinterpret_cast<TMappedFileLoad>(gs_MappedFileLoadPtr)(&gs_vMappedFileBuffer[0]);
		if (gs_vMappedFileBuffer.empty())
			return bRet;

		gs_bMappedInit = true;
		DebugLogf("Mapped file initialized: %p", gs_vMappedFileBuffer.data());
	}

	void* pData = nullptr;
	if (gs_nArgType == ARG_TYPE_3_ARG)
	{
		if (gs_nCallConvType == CC_TYPE_THISCALL)
		{
			bRet = reinterpret_cast<TEterPackManagerGet_3_thiscall>(gs_EterPackManagerGetAddress)(
				reinterpret_cast<void*>(gs_EterPackManagerClassPtr), reinterpret_cast<void*>(&gs_vMappedFileBuffer[0]),
				stInputFileName.c_str(), &pData
			);
		}
		else
		{
			bRet = reinterpret_cast<TEterPackManagerGet_3_stdcall>(gs_EterPackManagerGetAddress)(
				reinterpret_cast<void*>(&gs_vMappedFileBuffer[0]), stInputFileName.c_str(), &pData
			);
		}
	}
	else if (gs_nArgType == ARG_TYPE_4_ARG) // 4 arg
	{
		if (gs_nCallConvType == CC_TYPE_THISCALL)
		{
			bRet = reinterpret_cast<TEterPackManagerGet_4_thiscall>(gs_EterPackManagerGetAddress)(
				reinterpret_cast<void*>(gs_EterPackManagerClassPtr), reinterpret_cast<void*>(&gs_vMappedFileBuffer[0]),
				stInputFileName.c_str(), &pData, 0
			);
		}
		else
		{
			bRet = reinterpret_cast<TEterPackManagerGet_4_stdcall>(gs_EterPackManagerGetAddress)(
				reinterpret_cast<void*>(&gs_vMappedFileBuffer[0]), stInputFileName.c_str(), &pData, 0
			);
		}
	}
	else // 5 arg
	{
		if (gs_nCallConvType == CC_TYPE_THISCALL)
		{
			bRet = reinterpret_cast<TEterPackManagerGet_5_thiscall>(gs_EterPackManagerGetAddress)(
				reinterpret_cast<void*>(gs_EterPackManagerClassPtr), reinterpret_cast<void*>(&gs_vMappedFileBuffer[0]),
				stInputFileName.c_str(), &pData, "...", 0
			);
		}
		else
		{
			bRet = reinterpret_cast<TEterPackManagerGet_5_stdcall>(gs_EterPackManagerGetAddress)(
				reinterpret_cast<void*>(&gs_vMappedFileBuffer[0]), stInputFileName.c_str(), &pData, "...", 0
			);
		}
	}
	DebugLogf("Result: %d Data ptr: %p", bRet ? 1 : 0, pData);
	if (!bRet || !pData)
		return bRet;

	if (!gs_MappedFileSizeOffset)
	{
		auto pStart = reinterpret_cast<uintptr_t>(&gs_vMappedFileBuffer[0]);
		while (!gs_MappedFileSizeOffset)
		{
			if (*(uintptr_t*)pStart == reinterpret_cast<uintptr_t>(pData)) // m_pbBufLinkData
			{
				gs_MappedFileSizeOffset = (pStart - reinterpret_cast<uintptr_t>(&gs_vMappedFileBuffer[0])) + sizeof(uintptr_t); // m_dwBufLinkSize
				DebugLogf("size offset: %p", reinterpret_cast<void*>(gs_MappedFileSizeOffset));
				break;
			}
			pStart++;
		}
	}

	auto dwMappedFileSize = *(uint32_t*)(reinterpret_cast<uintptr_t>(&gs_vMappedFileBuffer[0]) + gs_MappedFileSizeOffset);
	DebugLogf("Size: %u", dwMappedFileSize);
	if (!dwMappedFileSize)
		return bRet;

	std::vector <wchar_t> vBuffer(dwMappedFileSize);
	if (!ReadMemory(reinterpret_cast<void*>(pData), &vBuffer[0], dwMappedFileSize))
	{
		DebugLogf("read fail");
		return bRet;
	}

	if (vBuffer.empty())
	{
		DebugLogf("buffer null");
		return bRet;
	}
		
	auto vSubFolderList = DirectoryList(stOutputFileName);
	if (!vSubFolderList.empty())
	{
		for (const auto& stSubFolder : vSubFolderList)
			CreateDirectoryA(stSubFolder.c_str(), nullptr);
	}
	
	FILE* pFile = nullptr;
	fopen_s(&pFile, stOutputFileName.c_str(), "wb");
	if (!pFile)
	{
		DebugLogf("file can not open");
		return bRet;
	}
	fwrite(vBuffer.data(), 1, vBuffer.size(), pFile);
	fclose(pFile);

	bRet = true;
	return bRet;
}

bool UnpackList(const std::string& stListFileName)
{
	std::ifstream in(stListFileName);
	if (!in)
	{
		MessageBoxA(0, xorstr("list file can not read!").crypt_get(), "", 0);
		return false;
	}

	std::string stLine;
	while (std::getline(in, stLine))
	{
		if (stLine.empty())
			continue;
		DebugLogf("line: %s", stLine.c_str());

		auto stNewFileName = std::string(stLine);
		replaceAll(stNewFileName, xorstr("d:").crypt_get(), xorstr("d_").crypt_get());
		replaceAll(stNewFileName, xorstr("/").crypt_get(), xorstr("\\").crypt_get());

		auto stOutputPath = xorstr("dump\\").crypt_get();
		auto stOutput = stOutputPath + stNewFileName;

		if (!packGet(stLine, stOutput))
		{
			std::ofstream f(xorstr("unpack.log").crypt_get(), std::ofstream::out | std::ofstream::app);
			f << xorstr("File: ").crypt_get() << stLine << xorstr(" can NOT unpacked!").crypt_get() << std::endl;
			f.close();
		}
	}

	in.close();
	MessageBoxA(0, xorstr("completed!").crypt_get(), 0, 0);
	return true;
}

DWORD WINAPI UnpackWorker(LPVOID)
{
	MessageBoxA(0, xorstr("Initialized!").crypt_get(), "", 0);

	// Check arg types
	switch (gs_nArgType)
	{
		case ARG_TYPE_3_ARG:
		case ARG_TYPE_4_ARG:
		case ARG_TYPE_5_ARG:
			break;
		default:
			MessageBoxA(0, xorstr("Unknown arg count").crypt_get(), std::to_string(gs_nArgType).c_str(), 0);
			abort();
//			DebugLogf("Unknown arg count: %u Converted to default(3)", gs_nArgType);
//			gs_nArgType = ARG_TYPE_3_ARG;
			break;
	}
	DebugLogf("Arg count type: %u", gs_nArgType);

	// Check call conv. types
	switch (gs_nCallConvType)
	{
		case CC_TYPE_STDCALL:
		case CC_TYPE_THISCALL:
			break;
		default:
			MessageBoxA(0, xorstr("Unknown call conv. type").crypt_get(), std::to_string(gs_nCallConvType).c_str(), 0);
			abort();
	}
	DebugLogf("Call conv type: %u", gs_nCallConvType);

	if (!std::filesystem::exists(xorstr("dump").crypt_get()))
		std::filesystem::create_directory(xorstr("dump").crypt_get());

	UnpackList(xorstr("list.txt").crypt_get());
	return 0;
}

bool AnalyseArgCount(uintptr_t pStartAddr, uintptr_t pEndAddr)
{
	if (gs_nArgType) // already defined by config
		return true;

	pStartAddr += 0x5; // skip curr func(tracef) call
//	dwEndAddr -= 1; // skip next func(eterpackmanager::get) call
	DebugLogf("AnalyseArgCount %p-%p(%u)", pStartAddr, pEndAddr, pEndAddr - pStartAddr);

	auto nPushCount = 0;
	auto pCurrAddr = pStartAddr;
	while (pCurrAddr < pEndAddr)
	{
		auto pCurrByte = *(uint8_t*)pCurrAddr;
		if (pCurrByte >= 0x50 && pCurrByte <= 0x57) // https://i.vgy.me/XXeaWZ.png
		{
			DebugLogf("push opcode found: 0x%X", pCurrByte);
			nPushCount++;
		}
		pCurrAddr++;
	}
	DebugLogf("push count: %d", nPushCount);

	if (nPushCount == 3)
		gs_nArgType = ARG_TYPE_3_ARG;
	else if (nPushCount == 4)
		gs_nArgType = ARG_TYPE_4_ARG;
	else if (nPushCount == 5)
		gs_nArgType = ARG_TYPE_5_ARG;

	return (gs_nArgType != ARG_TYPE_NULL);
}

void MainRoutine()
{
	uintptr_t pFuncAddress = 0;
	std::ifstream in(xorstr("unpack_config.txt").crypt_get(), std::ios_base::binary);
	if (in)
	{
		auto nLine = 0;
		std::string stLine;
		while (std::getline(in, stLine))
		{
			nLine++;
			if (stLine.empty())
				continue;
			DebugLogf("config line: %d) %s", nLine, stLine.c_str());

			switch (nLine)
			{
				case 1: // CPythonNonPlayer::LoadNonPlayerData func address
				{
					std::stringstream ss;
					ss << stLine;

					uintptr_t pAddress = 0;
					ss >> std::hex >> pFuncAddress;

					DebugLogf("Func address: %p", pFuncAddress);
				} break;

				case 2: // Arg count
				{
					auto nArgCount = std::stoi(stLine);

					if (nArgCount == 3)
						gs_nArgType = ARG_TYPE_3_ARG;
					else if (nArgCount == 4)
						gs_nArgType = ARG_TYPE_4_ARG;
					else if (nArgCount == 5)
						gs_nArgType = ARG_TYPE_5_ARG;
				} break;

				case 3: // Call conv. type
				{
					auto nCallConvType = std::stoi(stLine);

					if (nCallConvType == 1)
						gs_nCallConvType = CC_TYPE_THISCALL;
					else if (nCallConvType == 2)
						gs_nCallConvType = CC_TYPE_STDCALL;
				} break;
			}
		}
		in.close();
	}
	else
	{
		// 43 50 79 74 68 6F 6E 4E 6F 6E 50 6C 61 79 65 72 3A 3A 4C 6F 61 64 4E 6F 6E 50 6C 61 79 65 72 44 61 74 61 3A 20 25 73
		// CPythonNonPlayer::LoadNonPlayerData: %s
		auto arrBytes = std::array <uint8_t, 39> {
			0x43, 0x50, 0x79, 0x74, 0x68, 0x6F, 0x6E, 0x4E, 0x6F, 0x6E, 0x50, 0x6C, 0x61, 0x79,
			0x65, 0x72, 0x3A, 0x3A, 0x4C, 0x6F, 0x61, 0x64, 0x4E, 0x6F, 0x6E, 0x50, 0x6C, 0x61,
			0x79, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x3A, 0x20, 0x25, 0x73
		};
		const auto c_szMask = xorstr("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").crypt_get();

		auto pStringPattern = std::make_shared<SPattern>(c_szMask, arrBytes.data());
		if (!pStringPattern.get())
		{
			MessageBoxA(0, xorstr("SPattern init fail").crypt_get(), 0, 0);
			return;
		}

		auto pStringAddress = SearchPattern(pStringPattern);
		if (!pStringAddress)
		{
			MessageBoxA(0, xorstr("SearchPattern fail").crypt_get(), 0, 0);
			return;
		}
		arrBytes.fill(0x0);
		pStringPattern.reset();
		DebugLogf("String address: %p", pStringAddress);

		pFuncAddress = SearchFunction(pStringAddress);
		if (!pFuncAddress)
		{
			MessageBoxA(0, xorstr("SearchFunction fail").crypt_get(), 0, 0);
			return;
		}
		DebugLogf("Func address: %p", pFuncAddress);
	}

	auto hUser32 = LoadLibraryA(xorstr("user32.dll").crypt_get());
	if (!hUser32)
	{
		MessageBoxA(0, xorstr("LoadLibraryA fail").crypt_get(), 0, 0);
		return;
	}
	auto pMessageBox = reinterpret_cast<uintptr_t>(GetProcAddress(hUser32, xorstr("MessageBoxA").crypt_get()));
	if (!pMessageBox)
	{
		MessageBoxA(0, xorstr("GetProcAddress fail").crypt_get(), 0, 0);
		return;
	}
	DebugLogf("Messagebox %p", pMessageBox);


	auto vCallPtrs = std::vector<uintptr_t>();
	auto dwMFileCall = 0UL;
	auto dwStart = pFuncAddress;

	while (vCallPtrs.size() != 3)
	{
		if (*(uint8_t*)dwStart == 0xE8)
		{
			vCallPtrs.emplace_back(dwStart);
			DebugLogf("%u) %p", vCallPtrs.size(), dwStart);
		}
		dwStart++;
	}
	for (const auto& ptr : vCallPtrs)
	{
		DebugLogf("%p) %p", ptr, Relative2Absolute(ptr, 1, 5));
	}
	auto dwTracefCallAddr = vCallPtrs.at(0);

	// ---

	dwStart = pFuncAddress;

	while (!dwMFileCall)
	{
		dwStart--;

		if (*(uint8_t*)dwStart == 0xE8)
			dwMFileCall = dwStart;
	}

	// ---
	// 

	// -1 (logdan önceki ilk call)
	gs_MappedFileLoadPtr = reinterpret_cast<uintptr_t>(Relative2Absolute(dwMFileCall, 1, 5));
	if (!gs_MappedFileLoadPtr)
	{
		MessageBoxA(0, xorstr("Address1 find fail").crypt_get(), 0, 0);
		return;
	}
	DebugLogf("gs_MappedFileLoadPtr: %p", reinterpret_cast<void*>(gs_MappedFileLoadPtr));

	// 1
	// Tracef("CPythonNonPlayer::LoadNonPlayerData: %s, sizeof(TMobTable)=%u\n", c_szFileName, sizeof(TMobTable));

	uintptr_t pMemMsgBoxAddr = 0;
	// Type 1: Singleton informations (martysama v10)
	{
		auto dwBase = vCallPtrs.at(0); // Base: Tracef call addr
		auto dwCurrAddr = dwBase;
		while (dwCurrAddr < dwBase + 0x40)
		{
			auto wCurrBytes = *(uint16_t*)dwCurrAddr;
			// DebugLogf("cur: %p", wCurrBytes);

			if (wCurrBytes == 0x15FF) // call ds:????
			{
				auto dwApiAddr = *(uint32_t*)(dwCurrAddr + sizeof(uint16_t));
				auto dwApiPtr = *(uint32_t*)dwApiAddr;
				DebugLogf("dwApiPtr: %p", dwApiPtr);
				if (dwApiPtr == pMessageBox)
				{
					pMemMsgBoxAddr = dwCurrAddr;
					DebugLogf("msgbox found");
				}
				break;
			}
			dwCurrAddr++;
		}
	}
	if (pMemMsgBoxAddr) // If messagebox found in target mem re-sort call addresses with start than msgbox addr
	{
		vCallPtrs.clear();
		dwStart = pMemMsgBoxAddr;
		vCallPtrs.push_back(dwTracefCallAddr);

		while (vCallPtrs.size() != 3)
		{
			if (*(uint8_t*)dwStart == 0xE8)
			{
				vCallPtrs.emplace_back(dwStart);
				DebugLogf("%u) %p", vCallPtrs.size(), dwStart);
			}
			dwStart++;
		}
	}

	// Type 2: get ecx from offset
	if (!gs_EterPackManagerClassPtr)
	{
		// 2
		auto dwBase = vCallPtrs.at(0); // Base: Tracef call addr
		auto dwCurrAddr = dwBase;
		DebugLogf("Log call: %p", dwBase);

		while (dwCurrAddr < dwBase + 0x20)
		{
			auto wCurrBytes = *(uint16_t*)dwCurrAddr;
			// DebugLogf("cur: %p", wCurrBytes);

			if (wCurrBytes == 0x0D8B) // mov ecx, ????
			{
	 			auto dwEcx = *(uint32_t*)(dwCurrAddr + sizeof(uint16_t));
				DebugLogf("Ecx offset: %p", dwEcx);
				gs_EterPackManagerClassPtr = *(uint32_t*)dwEcx;
				break;
			}
			dwCurrAddr++;
		}
		DebugLogf("1/ gs_EterPackManagerClassPtr: %p", reinterpret_cast<void*>(gs_EterPackManagerClassPtr));
		if (gs_EterPackManagerClassPtr)
		{
			if (gs_nCallConvType == CC_TYPE_STDCALL)
			{
				if (AnalyseArgCount(vCallPtrs.at(0), vCallPtrs.at(1)))
					gs_EterPackManagerGetAddress = reinterpret_cast<uintptr_t>(Relative2Absolute(vCallPtrs.at(1), 1, 5));

				else if (AnalyseArgCount(vCallPtrs.at(1), vCallPtrs.at(2)))
					gs_EterPackManagerGetAddress = reinterpret_cast<uintptr_t>(Relative2Absolute(vCallPtrs.at(2), 1, 5));

				DebugLogf("gs_EterPackManagerGetAddress: %p", reinterpret_cast<void*>(gs_EterPackManagerGetAddress));
				if (!gs_EterPackManagerGetAddress)
				{
					MessageBoxA(0, xorstr("Address3 find fail").crypt_get(), 0, 0);
					return;
				}
			}
			else // if (gs_nCallConvType == CC_TYPE_THISCALL)
			{
				gs_nCallConvType = CC_TYPE_THISCALL;

				if (AnalyseArgCount(vCallPtrs.at(0), vCallPtrs.at(1)))
					gs_EterPackManagerGetAddress = reinterpret_cast<uintptr_t>(Relative2Absolute(vCallPtrs.at(1), 1, 5));

				else if (AnalyseArgCount(vCallPtrs.at(1), vCallPtrs.at(2)))
					gs_EterPackManagerGetAddress = reinterpret_cast<uintptr_t>(Relative2Absolute(vCallPtrs.at(2), 1, 5));

				// 3
				DebugLogf("gs_EterPackManagerGetAddress: %p", reinterpret_cast<void*>(gs_EterPackManagerGetAddress));
				if (!gs_EterPackManagerGetAddress)
				{
					MessageBoxA(0, xorstr("Address3 find fail").crypt_get(), 0, 0);
					return;
				}
			}
		}
	}
	// Type 3: get ecx from his special func
	if (!gs_EterPackManagerGetAddress)
	{
		// 2
		auto pClassPtrGet = reinterpret_cast<TEterClassFindFunc>(Relative2Absolute(vCallPtrs.at(1), 1, 5));
		DebugLogf("pClassPtrGet: %p", reinterpret_cast<void*>(pClassPtrGet));
		if (!pClassPtrGet)
		{
			MessageBoxA(0, xorstr("Address2.1 find fail").crypt_get(), 0, 0);
			return;
		}

		gs_EterPackManagerClassPtr = reinterpret_cast<uintptr_t>(pClassPtrGet());
		DebugLogf("2/ gs_EterPackManagerClassPtr: %p", reinterpret_cast<void*>(gs_EterPackManagerClassPtr));
		if (!gs_EterPackManagerClassPtr)
		{
			MessageBoxA(0, xorstr("Address2.2 find fail").crypt_get(), 0, 0);
			return;
		}

		gs_nCallConvType = CC_TYPE_THISCALL;
		AnalyseArgCount(vCallPtrs.at(1), vCallPtrs.at(2));

		// 3
		gs_EterPackManagerGetAddress = reinterpret_cast<uintptr_t>(Relative2Absolute(vCallPtrs.at(2), 1, 5));
		DebugLogf("gs_EterPackManagerGetAddress: %p", reinterpret_cast<void*>(gs_EterPackManagerGetAddress));
		if (!gs_EterPackManagerGetAddress)
		{
			MessageBoxA(0, xorstr("Address3 find fail").crypt_get(), 0, 0);
			return;
		}
	}

	auto dwThreadId = 0UL;
	auto hThread = CreateThread(0, 0, UnpackWorker, 0, 0, &dwThreadId);

	DebugLogf("UnpackWorker thread created: %p(%u)", hThread, dwThreadId);

	if (hThread && hThread != INVALID_HANDLE_VALUE)
		CloseHandle(hThread);
}

DWORD WINAPI Initialize(LPVOID)
{
	for (;;)
	{
		if (GetAsyncKeyState(VK_F5) & 0x8000) // down key
		{
			while (GetAsyncKeyState(VK_F5) & 0x8000) // wait for up key
				Sleep(1);

			MainRoutine();
			return 0;
		}
		Sleep(100);
	}
	return 0;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
	static auto initialized = false;

	if (initialized == false)
	{
		initialized = true;
		CreateThread(0, 0, Initialize, 0, 0, 0);
	}

	return TRUE;
}
