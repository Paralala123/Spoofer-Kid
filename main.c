#include "stdafx.h"
#include <filesystem>

int main() {
	srand(GetTickCount());
	LoadLibrary(L"ntdll.dll");
	NtQueryKey = (NTQK)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryKey");
	if (!AdjustCurrentPrivilege(SE_TAKE_OWNERSHIP_NAME)) {
		printf("failed to adjust privilege\n");
		return 1;
	}

	/
	
	// Misc
	DeleteKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\MountedDevices");
	DeleteKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Dfrg\\Statistics");
	DeleteKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume");
	DeleteKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume");
	DeleteKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2");
	DeleteValue(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket", L"LastEnum");

	SpoofBinary(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", L"WindowsAIKHash");
	SpoofBinary(HKEY_CURRENT_USER, L"Software\\Microsoft\\Direct3D", L"WHQLClass");
	SpoofBinary(HKEY_CURRENT_USER, L"Software\\Classes\\Installer\\Dependencies", L"MSICache");

	OpenThen(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral", {
		ForEachSubkey(key, {
			SpoofUnique(key, name, L"Identifier");
		});
	});

	
	
	// Equ8 Clear
	DeleteKey(HKEY_CURRENT_USER, L"SOFTWARE\\Landfall Games");
	system("rd /s /q C:\\ProgramData\\EQU8");

	// Tracking files
	WCHAR path[MAX_PATH] = { 0 };
	WCHAR temp[MAX_PATH] = { 0 };
	WCHAR appdata[MAX_PATH] = { 0 };
	WCHAR localappdata[MAX_PATH] = { 0 };
	GetTempPath(MAX_PATH, temp);

	SHGetFolderPath(0, CSIDL_APPDATA, 0, SHGFP_TYPE_DEFAULT, appdata);
	SHGetFolderPath(0, CSIDL_LOCAL_APPDATA, 0, SHGFP_TYPE_DEFAULT, localappdata);

	wsprintf(path, L"%ws*", temp);
	ForEachFile(path, {
		wsprintf(path, L"%ws%ws", temp, file);
		ForceDeleteFile(path);
	});

	wsprintf(path, L"%ws\\D3DSCache", localappdata);
	ForceDeleteFile(path);

	
	wsprintf(path, L"%ws\\Microsoft\\Feeds", localappdata);
	ForceDeleteFile(path);

	wsprintf(path, L"%ws\\Microsoft\\Feeds Cache", localappdata);
	ForceDeleteFile(path);

	wsprintf(path, L"%ws\\Microsoft\\Windows\\INetCache", localappdata);
	ForceDeleteFile(path);

	wsprintf(path, L"%ws\\Microsoft\\Windows\\INetCookies", localappdata);
	ForceDeleteFile(path);


	for (DWORD drives = GetLogicalDrives(), drive = L'C', index = 0; drives; drives >>= 1, ++index) {
		if (drives & 1) {
			printf("\n-- DRIVE: %c --\n\n", drive);

			// Volume serial change applies after restart
			wsprintf(path, L"\\\\.\\%c:", drive);
			HANDLE device = CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			if (device != INVALID_HANDLE_VALUE) {
				BYTE sector[512] = { 0 };
				DWORD read = 0;
				if (ReadFile(device, sector, sizeof(sector), &read, 0) && read == sizeof(sector)) {
					for (DWORD i = 0; i < LENGTH(SECTORS); ++i) {
						PSECTOR s = &SECTORS[i];
						if (0 == memcmp(sector + s->NameOffset, s->Name, strlen(s->Name))) {
							*(PDWORD)(sector + s->SerialOffset) = (rand() << 16) + rand();
							if (INVALID_SET_FILE_POINTER != SetFilePointer(device, 0, 0, FILE_BEGIN)) {
								WriteFile(device, sector, sizeof(sector), 0, 0);
							}

							break;
						}
					}
				}

				CloseHandle(device);
			}

			wsprintf(path, L"%c:\\Windows\\System32\\restore\\MachineGuid.txt", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Users\\Public\\Libraries\\collection.dat", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\System Volume Information\\IndexerVolumeGuid", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\System Volume Information\\WPSettings.dat", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\System Volume Information\\tracking.log", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\ProgramData\\Microsoft\\Windows\\WER", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Users\\Public\\Shared Files", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Windows\\INF\\setupapi.dev.log", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Windows\\INF\\setupapi.setup.log", drive);
			ForceDeleteFile(path);

			// wsprintf(path, L"%c:\\Windows\\System32\\spp\\store", drive);
			// ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Users\\Public\\Libraries", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\MSOCache", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\ProgramData\\ntuser.pol", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Users\\Default\\NTUSER.DAT", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Recovery\\ntuser.sys", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\desktop.ini", drive);
			ForceDeleteFile(path);

			wsprintf(path, L"%c:\\Windows\\Prefetch\\*", drive);
			ForEachFile(path, {
				wsprintf(path, L"%c:\\Windows\\Prefetch\\%ws", drive, file);
				ForceDeleteFile(path);
			});

			wsprintf(path, L"%c:\\Users\\*", drive);
			ForEachFile(path, {
				if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					WCHAR user[MAX_PATH] = { 0 };
					wcscpy(user, file);
					wsprintf(path, L"%c:\\Users\\%ws\\*", drive, user);
					ForEachFile(path, {
						if (StrStr(file, L"ntuser")) {
							wsprintf(path, L"%c:\\Users\\%ws\\%ws", drive, user, file);
							ForceDeleteFile(path);
						}
					});
				}
			});

			wsprintf(path, L"%c:\\Users", drive);
			RecursiveDelete(path, L"desktop.ini");

			CHAR journal[MAX_PATH] = { 0 };
			sprintf(journal, "fsutil usn deletejournal /d %c:", drive);
			system(journal);

			++drive;
		}
	}

	// Extra cleanup
	system("vssadmin delete shadows /All /Quiet");

	// WMIC holds cache of SMBIOS. With the driver loaded, starting WMIC will query the nulled SMBIOS data
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot) {
		PROCESSENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);
		if (Process32First(snapshot, &entry)) {
			do {
				// Sometimes 'net stop' by itself isn't enough
				if (0 == _wcsicmp(entry.szExeFile, L"WmiPrvSE.exe")) {
					HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 0, entry.th32ProcessID);
					if (INVALID_HANDLE_VALUE != process) {
						printf("Killed Winmgmt\n");
						TerminateProcess(process, 0);
						CloseHandle(process);
					}

					break;
				}
			} while (Process32Next(snapshot, &entry));
		}

		CloseHandle(snapshot);
	}

	system("net stop winmgmt /Y");

	system("pause");

	return 0;
}
