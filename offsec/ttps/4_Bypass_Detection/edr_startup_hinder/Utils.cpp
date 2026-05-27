#include "Utils.h"

BOOL CopyAndPatchFile(std::wstring srcPath, std::wstring dstPath)
{
    if (!CopyFileW(srcPath.c_str(), dstPath.c_str(), FALSE))
    {
        std::wcerr << L"CopyFileW failed with error: " << GetLastError() << std::endl;
        return false;
    }

    HANDLE hFile = CreateFileW(dstPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"CreateFileW failed with error: " << GetLastError() << std::endl;
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE)
    {
        CloseHandle(hFile);
        return false;
    }

    BYTE* buffer = new BYTE[fileSize];
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, nullptr))
    {
        delete[] buffer;
        CloseHandle(hFile);
        return false;
    }

    const char* target = "This program cannot be run in DOS mode";
    for (DWORD i = 0; i < fileSize - strlen(target); ++i)
    {
        if (memcmp(buffer + i, target, strlen(target)) == 0)
        {
            buffer[i] = 'H'; // Replace 'T' with 'H'
            break;
        }
    }

    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    DWORD bytesWritten = 0;
    if (!WriteFile(hFile, buffer, fileSize, &bytesWritten, nullptr))
    {
        delete[] buffer;
        CloseHandle(hFile);
        return false;
    }

    delete[] buffer;
    CloseHandle(hFile);
    return true;
}

BOOL IsProcessRunning(std::wstring processName)
{
    bool found = false;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32))
    {
        do
        {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0)
            {
                found = true;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return found;
}


BOOL CreateNewService(std::wstring serviceName, std::wstring displayName, std::wstring groupName, std::wstring imagePath)
{

    SC_HANDLE hSCM = OpenSCManagerW( nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM)
    {
        std::wcerr << L"OpenSCManager failed, error: " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE hService = CreateServiceW(
        hSCM,
        serviceName.c_str(),    // internal service name
        displayName.c_str(),    // display name
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,     // auto start
        SERVICE_ERROR_NORMAL,
        imagePath.c_str(),      // binary path
        groupName.c_str(),      // load order group
        nullptr,                // tag ID
        nullptr,                // dependencies
        L"LocalSystem",         // run as SYSTEM
        nullptr                 // no password
    );

    if (!hService)
    {
        std::wcerr << L"CreateService failed, error: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCM);
        return false;
    }
    std::wcout << L"Service created successfully!" << std::endl;
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

BOOL IsRunningAsService()
{
    DWORD sessionId = 0;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &sessionId))
    {
        if (sessionId == 0)
        {
            return true; // Session 0 → likely a service
        }
    }
    return false;
}

BOOL EnsureDirectoryExists(std::wstring fullFilePath)
{
    // Extract directory part from full file path
    size_t pos = fullFilePath.find_last_of(L"\\/");
    if (pos == std::wstring::npos)
    {
        std::wcerr << L"Invalid file path: " << fullFilePath << std::endl;
        return false;
    }

    std::wstring dirPath = fullFilePath.substr(0, pos);

    // Create all intermediate directories
    int result = SHCreateDirectoryExW(nullptr, dirPath.c_str(), nullptr);

    if (result == ERROR_SUCCESS || result == ERROR_ALREADY_EXISTS)
    {
        return true; // directory created or already exists
    }

    std::wcerr << L"SHCreateDirectoryExW failed, error: " << result << std::endl;
    return false;
}

std::wstring GetCurrentProcessPath()
{
    wchar_t buffer[MAX_PATH];
    DWORD length = GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    if (length == 0)
    {
        std::wcerr << L"GetModuleFileNameW failed, error: " << GetLastError() << std::endl;
        return L"";
    }
    return std::wstring(buffer, length);
}

std::wstring GetCurrentProcessDirectoryOnly()
{
    wchar_t buffer[MAX_PATH];
    DWORD length = GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    if (length == 0) {
        std::wcerr << L"GetModuleFileNameW failed, error: " << GetLastError() << std::endl;
        return L"";
    }

    std::wstring fullPath(buffer, length);

    // Find last backslash
    size_t pos = fullPath.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return L""; // no directory part
    }

    return fullPath.substr(0, pos);
}

VOID AppendLog(std::wstring logEntry)
{
    std::wofstream logFile;
    logFile.open(GetCurrentProcessDirectoryOnly() + L"\\RunLog.txt", std::ios::app);
    if (!logFile.is_open())
    {
        std::wcerr << L"Failed to open RunLog.txt for writing." << std::endl;
        return;
    }
    logFile << logEntry << std::endl;
    logFile.close();
}