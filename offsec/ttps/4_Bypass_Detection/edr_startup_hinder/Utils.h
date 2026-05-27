#pragma once
#include <windows.h>
#include <string>
#include <iostream>
#include <fstream>
#include <tlhelp32.h>
#include <shlobj.h>

#pragma comment(lib, "Shell32.lib")

BOOL CopyAndPatchFile(std::wstring srcPath, std::wstring dstPath);

BOOL IsProcessRunning(std::wstring processName);

BOOL CreateNewService(std::wstring serviceName, std::wstring displayName,  std::wstring groupName, std::wstring imagePath);

BOOL IsRunningAsService();

BOOL EnsureDirectoryExists(std::wstring fullFilePath);

std::wstring GetCurrentProcessPath();

std::wstring GetCurrentProcessDirectoryOnly();

VOID AppendLog(std::wstring logEntry);