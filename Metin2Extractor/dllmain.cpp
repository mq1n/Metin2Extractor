#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <memory>
#include <regex>
#include <array>
#include <fstream>
#include "xorstr.hpp"

#define NtCurrentProcess ((HANDLE)-1)

void DebugLog(const char* c_szLogData)
{
	OutputDebugStringA(c_szLogData);
}

void DebugLogf(const char* c_szFormat, ...)
{
	char szBuffer[100000];

	va_list vaArgList;
	va_start(vaArgList, c_szFormat);
	vsprintf_s(szBuffer, c_szFormat, vaArgList);
	va_end(vaArgList);

	DebugLog(szBuffer);
}


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


inline bool ReadMemory(void* address, void* buffer, size_t size)
{
	ULONG dwReadByteCount = 0;
	ULONG dwOldProtect = 0;
	__try
	{
		if (VirtualProtectEx(NtCurrentProcess, address, size, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			if (!ReadProcessMemory(NtCurrentProcess, address, buffer, size, &dwReadByteCount))
			{
				DebugLogf("ReadProcessMemory fail! Error: %u", GetLastError());
				dwReadByteCount = 0;
			}

			VirtualProtectEx(NtCurrentProcess, address, size, dwOldProtect, &dwOldProtect);
		}
		else
		{
			DebugLogf("VirtualProtectEx(pre) fail! Error: %u", GetLastError());
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DebugLogf("exception");
	}

	return (dwReadByteCount && dwReadByteCount == size);
}

inline uint32_t FindPattern(uint8_t* address, size_t size, const std::shared_ptr <SPattern>& pattern)
{
	std::vector <uint8_t> buffer(size);

	if (!ReadMemory(address, &buffer[0], size))
	{
		DebugLogf("Read fail ||| %p - %u(real) - %u(read) | %p\n", address, size, buffer.size(), pattern->GetBytes());
		return 0;
	}

	uint32_t dwResult = 0;
	for (size_t i = 0; i + pattern->GetLength() < buffer.size(); ++i)
	{
		auto bFound = true;
		for (uint32_t j = 0UL; j < pattern->GetLength() && bFound; ++j)
		{
			if (pattern->GetMask(j) == '?')
				continue;
			if (pattern->GetByte(j) == buffer[i + j])
				continue;

			bFound = false;
		}

		if (bFound)
		{
			dwResult = (uint32_t)address + i;
			break;
		}
	}

	return dwResult;
}

uintptr_t SearchPattern(std::shared_ptr <SPattern> pattern)
{
	uint32_t target = 0;
	uint32_t baseAddress = 0;
	MEMORY_BASIC_INFORMATION basicInfo = { 0 };

	auto bufferSize = 0ULL;
	while (bufferSize = VirtualQueryEx(NtCurrentProcess, reinterpret_cast<LPCVOID>(baseAddress), &basicInfo, sizeof(basicInfo)))
	{
		//		char msg[128] = { 0 };
		//		sprintf_s(msg, "Current region: %p-%u", basicInfo.BaseAddress, basicInfo.RegionSize);
		//		OutputDebugStringA(msg);

		if (reinterpret_cast<uint32_t>(basicInfo.BaseAddress) < 0x400000)
			goto ContinueLoop;

		if (basicInfo.State != MEM_COMMIT)
			goto ContinueLoop;
		if (basicInfo.Protect == PAGE_NOACCESS)
			goto ContinueLoop;
		if (basicInfo.Protect & PAGE_GUARD)
			goto ContinueLoop;

		target = FindPattern(reinterpret_cast<uint8_t*>(basicInfo.BaseAddress), basicInfo.RegionSize, pattern);
		if (target)
			break;

	ContinueLoop:
		baseAddress += basicInfo.RegionSize;
	}

	return target;
}

uint32_t SearchFunction(uint32_t dwRefAddr)
{
	uint32_t target = 0;
	auto baseAddress = (uint32_t)GetModuleHandleA(0);

	uint32_t dwStart = 0;
	uint32_t dwEnd = 0;

	auto bufferSize = 0ULL;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	while (bufferSize = VirtualQueryEx(NtCurrentProcess, reinterpret_cast<LPCVOID>(baseAddress), &mbi, sizeof(mbi)))
	{
		if (mbi.State != MEM_COMMIT)
			goto ContinueLoop;

		switch (mbi.Protect)
		{
		case PAGE_READONLY:
		case PAGE_READWRITE:
		case PAGE_EXECUTE_READ:
		case PAGE_EXECUTE_READWRITE:
			break;
		default:
			goto ContinueLoop;
		}

		dwStart = (uint32_t)mbi.BaseAddress;
		dwEnd = (uint32_t)mbi.BaseAddress + mbi.RegionSize;

		//		char msg[120];
		//		sprintf_s(msg, "Start: %p End: %p", dwStart, dwEnd);
		//		OutputDebugStringA(msg);

		while (*(uint32_t*)dwStart != dwRefAddr && dwStart < dwEnd)
			dwStart++;

		if (dwStart != dwEnd)
		{
			target = dwStart;
			break;
		}

	ContinueLoop:
		baseAddress += mbi.RegionSize;
	}

	//	sprintf_s(msg, "Found: %p", dwStart);
	//	OutputDebugStringA(msg);

	return dwStart;
}

#define Relative2Absolute(pBase, dwOffset, dwLength) (PVOID)((SIZE_T)pBase + (*(PLONG)((PBYTE)pBase + dwOffset)) + dwLength)

typedef void* (__cdecl* TEterClassFindFunc)();
typedef void* (__thiscall* TMappedFileLoad)(void* This);
typedef bool(__thiscall* TEterPackManagerGet)(void* This, void* rMappedFile, const char* c_szFileName, LPVOID * data);

static uintptr_t gs_MappedFileSizeOffset = 0;
static uintptr_t gs_MappedFileLoadPtr = 0;
static uintptr_t gs_EterPackManagerClassPtr = 0;
static uintptr_t gs_EterPackManagerGetAddress = 0;

static bool gs_bMappedInit = false;
static std::vector <uint8_t> gs_vMappedFileBuffer(0x2000);

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

bool packGet(const std::string& stInputFileName, std::string stOutputFileName)
{
	bool bRet = false;

	DebugLogf("In: %s Out: %s", stInputFileName.c_str(), stOutputFileName.c_str());

	if (!gs_bMappedInit)
	{
		reinterpret_cast<TMappedFileLoad>(gs_MappedFileLoadPtr)(&gs_vMappedFileBuffer[0]);
		if (gs_vMappedFileBuffer.empty())
			return bRet;

		gs_bMappedInit = true;
		DebugLogf("Mapped file initialized");
	}

	void* pData = nullptr;
	bRet = reinterpret_cast<TEterPackManagerGet>(gs_EterPackManagerGetAddress)(
		(void*)gs_EterPackManagerClassPtr, (void*)& gs_vMappedFileBuffer[0], stInputFileName.c_str(), &pData
	);
	if (!bRet || !pData)
		return bRet;

	if (!gs_MappedFileSizeOffset)
	{
		auto dwStart = (uint32_t)&gs_vMappedFileBuffer[0];
		while (!gs_MappedFileSizeOffset)
		{
			if (*(uint32_t*)dwStart == (uint32_t)pData) // m_pbBufLinkData
			{
				gs_MappedFileSizeOffset = (dwStart - (uint32_t)&gs_vMappedFileBuffer[0]) + sizeof(uint32_t); // m_dwBufLinkSize
				DebugLogf("size offset: %p", (void*)gs_MappedFileSizeOffset);
				break;
			}
			dwStart++;
		}
	}

	auto dwMappedFileSize = *(uint32_t*)((uint32_t)&gs_vMappedFileBuffer[0] + gs_MappedFileSizeOffset);
	// DebugLogf("Size: %u", dwMappedFileSize);
	if (!dwMappedFileSize)
		return bRet;

	std::vector<wchar_t> vBuffer(dwMappedFileSize);
	if (!ReadMemory((void*)pData, &vBuffer[0], dwMappedFileSize))
	{
		DebugLogf("read fail");
		return bRet;
	}

	if (vBuffer.empty())
	{
		DebugLogf("buffer null");
		return bRet;
	}
		
	auto directories = DirectoryList(stOutputFileName);
	if (!directories.empty())
	{
		for (const auto& current : directories)
			CreateDirectoryA(current.c_str(), nullptr);
	}
	
	FILE* pFile = nullptr;
	fopen_s(&pFile, stOutputFileName.c_str(), "wb");
	if (!pFile)
	{
		DebugLogf("file can not open");
		return bRet;
	}
	fwrite(vBuffer.data(), 1, vBuffer.size() - 1, pFile);
	fclose(pFile);

	bRet = true;
	return bRet;
}

bool UnpackList(const std::string& stListFileName)
{
	std::ifstream in(stListFileName);
	if (!in)
	{
		MessageBoxA(0, "list file can not read!", "", 0);
		return false;
	}

	std::string stLine;
	while (std::getline(in, stLine))
	{
		if (stLine.empty())
			continue;
		DebugLogf("line: %s", stLine.c_str());

		auto stNewFileName = std::string(stLine);
		replaceAll(stNewFileName, "d:", "d_");
		replaceAll(stNewFileName, "/", "\\");
		auto stOutput = "dump\\" + stNewFileName;

		if (!packGet(stLine, stOutput))
		{
			std::ofstream f("unpack.log", std::ofstream::out | std::ofstream::app);
			f << "File: " << stLine << " can NOT unpacked!" << std::endl;
			f.close();
		}
	}

	in.close();
	MessageBoxA(0, "completed!", 0, 0);
	return true;
}

DWORD WINAPI UnpackWorker(LPVOID)
{
	MessageBoxA(0, "Initialized!", "", 0);

	UnpackList("list.txt");
	return 0;
}

void MainRoutine()
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
		MessageBoxA(0, "SPattern init fail", 0, 0);
		return;
	}

	auto pStringAddress = SearchPattern(pStringPattern);
	if (!pStringAddress)
	{
		MessageBoxA(0, "SearchPattern fail", 0, 0);
		return;
	}
	arrBytes.fill(0x0);
	pStringPattern.reset();

	auto pFuncAddress = SearchFunction(pStringAddress);
	if (!pFuncAddress)
	{
		MessageBoxA(0, "SearchFunction fail", 0, 0);
		return;
	}

	auto vCallPtrs = std::vector<uintptr_t>();
	auto dwMFileCall = 0UL;
	auto dwStart = pFuncAddress;

	while (vCallPtrs.size() != 3)
	{
		if (*(BYTE*)dwStart == 0xE8)
			vCallPtrs.emplace_back(dwStart);
		dwStart++;
	}

	// ---

	dwStart = pFuncAddress;

	while (!dwMFileCall)
	{
		dwStart--;

		if (*(BYTE*)dwStart == 0xE8)
			dwMFileCall = dwStart;
	}

	// ---
	// 

	// -1 (logdan önceki ilk call)
	gs_MappedFileLoadPtr = (uintptr_t)Relative2Absolute(dwMFileCall, 1, 5);
	if (!gs_MappedFileLoadPtr)
	{
		MessageBoxA(0, xorstr("Address1 find fail").crypt_get(), 0, 0);
		return;
	}

	// 1
	// Tracef("CPythonNonPlayer::LoadNonPlayerData: %s, sizeof(TMobTable)=%u\n", c_szFileName, sizeof(TMobTable));

	// 2
	auto pClassPtrGet = (TEterClassFindFunc)Relative2Absolute(vCallPtrs.at(1), 1, 5);
	if (!pClassPtrGet)
	{
		MessageBoxA(0, xorstr("Address2.1 find fail").crypt_get(), 0, 0);
		return;
	}
	gs_EterPackManagerClassPtr = (uintptr_t)pClassPtrGet();
	if (!gs_EterPackManagerClassPtr)
	{
		MessageBoxA(0, xorstr("Address2.2 find fail").crypt_get(), 0, 0);
		return;
	}

	// 3
	gs_EterPackManagerGetAddress = (uintptr_t)Relative2Absolute(vCallPtrs.at(2), 1, 5);
	if (!gs_EterPackManagerGetAddress)
	{
		MessageBoxA(0, xorstr("Address3 find fail").crypt_get(), 0, 0);
		return;
	}

	CreateThread(0, 0, UnpackWorker, 0, 0, 0);
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
	static auto initialized = false;

	if (initialized == false)
	{
		initialized = true;
		MainRoutine();
	}

	return TRUE;
}

