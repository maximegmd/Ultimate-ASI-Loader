#include <filesystem>
#include <fstream>
#include <limits>

#include <Windows.h>

#include "simdjson.h"

#undef min
#undef max

#include <parallel_hashmap/phmap.h>
#include <parallel_hashmap/phmap_dump.h>

#pragma comment( lib, "version" )

struct AddressLibrary
{
    AddressLibrary(uint64_t version, const std::filesystem::path& root);
    void* Get(uint32_t aHash) const;

private:

    bool Load(const std::filesystem::path& cacheFile);
    void Build(const std::filesystem::path& root);
    bool Save(const std::filesystem::path& cacheFile) const;

    static std::vector<uint32_t> LoadSections();

    phmap::flat_hash_map<uint32_t, uint32_t> m_offsets;
    uint64_t m_base;
};

std::optional<uint64_t> GetGameVersion()
{
    std::wstring fileName;
    TCHAR exePathBuf[MAX_PATH] = { 0 };
    GetModuleFileNameW(GetModuleHandle(nullptr), exePathBuf, static_cast<DWORD>(std::size(exePathBuf)));

    fileName = exePathBuf;

    auto size = GetFileVersionInfoSizeW(fileName.c_str(), nullptr);
    if (!size)
    {
        throw std::runtime_error("Module has no size.");
    }

    std::unique_ptr<uint8_t[]> data(new (std::nothrow) uint8_t[size]());
    if (!data)
    {
        throw std::runtime_error("Cannot allocate memory.");
    }

    if (!GetFileVersionInfo(fileName.c_str(), 0, size, data.get()))
    {
        throw std::runtime_error("Module has no information.");
    }

    struct LangAndCodePage
    {
        WORD language;
        WORD codePage;
    }*translations;
    uint32_t translationsBytes;

    if (!VerQueryValue(data.get(), L"\\VarFileInfo\\Translation", reinterpret_cast<void**>(&translations), &translationsBytes))
    {
        throw std::runtime_error("Module has no translation information.");
    }

    bool isGame = false;

    for (uint32_t i = 0; i < (translationsBytes / sizeof(LangAndCodePage)); i++)
    {
        wchar_t* productName;
        auto subBlock = std::format(L"\\StringFileInfo\\{:04x}{:04x}\\ProductName", translations[i].language, translations[i].codePage);

        if (VerQueryValue(data.get(), subBlock.c_str(), reinterpret_cast<void**>(&productName), &translationsBytes))
        {
            constexpr std::wstring_view expectedProductName = L"Cyberpunk 2077";
            if (productName == expectedProductName)
            {
                isGame = true;
                break;
            }
        }
    }

    if (isGame)
    {
        VS_FIXEDFILEINFO* fileInfo = nullptr;
        UINT fileInfoBytes;

        if (!VerQueryValue(data.get(), L"\\", reinterpret_cast<LPVOID*>(&fileInfo), &fileInfoBytes))
        {
            throw std::runtime_error("Module has no information.");
        }

        constexpr auto signature = 0xFEEF04BD;
        if (fileInfo->dwSignature != signature)
        {
            return std::nullopt;
        }

        {
            uint64_t version = fileInfo->dwFileVersionMS;
            version <<= 32;
            version |= fileInfo->dwFileVersionLS;

            return version;
        }
    }

    return std::nullopt;

}

AddressLibrary::AddressLibrary(uint64_t version, const std::filesystem::path& root)
{
    m_base = reinterpret_cast<uint64_t>(GetModuleHandleA(nullptr));

    const auto cacheDir = root / "plugins" / "address_library";
    std::error_code ec;
    create_directories(cacheDir, ec);

    const auto cacheFile = cacheDir / ("version-" + std::to_string(version) + ".bin");
    if(exists(cacheFile))
    {
        Load(cacheFile);
    }

    if (m_offsets.empty())
    {
        Build(root);
        Save(cacheFile);
    }
}

void* AddressLibrary::Get(uint32_t aHash) const
{
	const auto offset = m_offsets.find(aHash);
    if (offset == std::end(m_offsets))
        return nullptr;

    return reinterpret_cast<void*>(m_base + offset->second);
}

bool AddressLibrary::Load(const std::filesystem::path& cacheFile)
{
    phmap::BinaryInputArchive in(cacheFile.generic_string().c_str());
    return m_offsets.phmap_load(in);
}

void AddressLibrary::Build(const std::filesystem::path& rootDir)
{
    auto path = rootDir / "cyberpunk2077_addresses.json";

    if (!exists(path))
    {
        return;
    }

    simdjson::ondemand::parser parser;
    simdjson::padded_string json = simdjson::padded_string::load(path.string());
    simdjson::ondemand::document document = parser.iterate(json);

    simdjson::ondemand::array root;
    auto error = document["Addresses"].get_array().get(root);
    if (error)
    {
        return;
    }

    auto sections = LoadSections();

    root.reset();

    for (auto entry : root)
    {
        auto hashField = entry.find_field("hash");
        auto offsetField = entry.find_field("offset");

        if (!hashField.error() && !offsetField.error())
        {
            std::uint64_t hash;
            error = hashField.get_uint64_in_string().get(hash);
            if (error)
            {
                return;
            }

            std::string_view offsetStr;
            error = offsetField.get_string().get(offsetStr);
            if (error)
            {
                return;
            }

            std::stringstream stream;
            stream << offsetStr;

            std::uint32_t segment;
            char separator;
            std::uint32_t offset;
            stream >> std::hex >> segment >> separator >> offset;

            offset += sections[segment - 1];

            m_offsets.emplace(static_cast<std::uint32_t>(hash), offset);
        }
    }
}

bool AddressLibrary::Save(const std::filesystem::path& cacheFile) const
{
    phmap::BinaryOutputArchive out(cacheFile.generic_string().c_str());
    return m_offsets.phmap_dump(out);
}

std::vector<uint32_t> AddressLibrary::LoadSections()
{
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule == NULL)
    {
        return {};
    }

    // Access the DOS header
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    // Access the PE header
    IMAGE_NT_HEADERS* peHeader = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);

    // Check for PE signature
    if (peHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return {};
    }

    std::vector<uint32_t> offsets;

    // Access the section headers
    IMAGE_SECTION_HEADER* sectionHeaders = IMAGE_FIRST_SECTION(peHeader);
    const int numberOfSections = peHeader->FileHeader.NumberOfSections;

    // List the sections
    for (int i = 0; i < numberOfSections; i++)
    {
        IMAGE_SECTION_HEADER* sectionHeader = &sectionHeaders[i];
        offsets.push_back(sectionHeader->VirtualAddress);
    }

    return offsets;
}

AddressLibrary* s_pLibrary;

void InitializeAddressLibrary(const std::filesystem::path& root)
{
    const auto version = GetGameVersion();
    if (!version)
        return;

	//while (!IsDebuggerPresent())
    //    Sleep(1000);

    s_pLibrary = new AddressLibrary(*version, root);
}

extern "C" void* ResolveAddress(uint32_t aHash)
{
    if (!s_pLibrary)
        return nullptr;

    return s_pLibrary->Get(aHash);
}