// Author: James Dickson 2018
// This Software is released under GPLv3 see GPL.txt (https://www.gnu.org/licenses/gpl.txt)
// Syfte: Exempel på hur trace-funktionen funkar i Windows.

#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <strsafe.h>
#include <wmistr.h>
#include <evntrace.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <tdh.h>



#define MAXIMUM_SESSION_NAME	1024
#define CURRENTWINMAXPATH		32767
#define MAXEXCLUDEPATHS			64

DWORD dwAccumulatedBytes = 0;		// Antalet bytes i loggfil
DWORD dwMaxOutputSize = 100000000;	// Typ 100mb innan vi skriver en ny fil


static GUID GUID_FILEIO = { 0x90cbdc39, 0x4a3e, 0x11d1,{ 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3 } };

typedef struct tagProcessTraceArguments
{
	TRACEHANDLE *traceHandle;
	WCHAR strOutputFile[1024];
	HANDLE hFile;

}ProcessTraceArguments, *LPProcessTraceArguments;

typedef struct
{
	ULONG_PTR pFileObject;
	WCHAR strFilename[1];
} FILEIODATA, *LPFILEIODATA;

typedef struct tagFILEIOCREATE
{
	UINT64 IrpPtr;
	UINT64 TTID;
	UINT32 FileObject;
	UINT32 CreateOptions;
	UINT32 FileAttributes;
	UINT32 ShareAccess;
	WCHAR strFilename[1];
} FILEIOCREATE, *LPFILEIOCREATE;


LPProcessTraceArguments		traceArgs = NULL;	// Global för callbacks
WCHAR strExcludePaths[MAXEXCLUDEPATHS][1024];	// Prefix för sökvägar som ska exkluderas
int excludePathsLengths[MAXEXCLUDEPATHS];		// Sökvägar att exkludera
int excludePathsCount = 0;						// Antal exkluderade sökvägar.
WCHAR *STR_LINEFEED = L"\r\n";					// CRLF

DWORD WINAPI  processTraceFunction(LPVOID lpParam)
{
	LPProcessTraceArguments traceArgs = (LPProcessTraceArguments)lpParam;
	ULONG result = ProcessTrace(traceArgs->traceHandle, 1, 0, 0);

	if (result != ERROR_SUCCESS && result != ERROR_CANCELLED)
	{
		wprintf(L"[-] ProcessTrace FEL %lu\n", result);
	}

	return 0;
}

HANDLE startProcessTrace(LPProcessTraceArguments traceArgs)
{
	DWORD   dwThreadId = 0;
	HANDLE  hThread  = CreateThread(NULL,0, processTraceFunction,traceArgs,0, &dwThreadId);   

	return hThread;
}


PEVENT_TRACE_PROPERTIES createTraceProps(HANDLE hProgHeap)
{
	PEVENT_TRACE_PROPERTIES traceProps = NULL;
	ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + (MAXIMUM_SESSION_NAME + MAX_PATH) * sizeof(WCHAR);

	traceProps = (PEVENT_TRACE_PROPERTIES)HeapAlloc(hProgHeap, 0, bufSize);

	if (traceProps == NULL) 
	{
		return NULL;
	}

	ZeroMemory(traceProps, bufSize);
	traceProps->Wnode.BufferSize = bufSize;
	traceProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	traceProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	traceProps->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + (MAXIMUM_SESSION_NAME * sizeof(WCHAR));
	traceProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	traceProps->Wnode.ClientContext = 1;	
	traceProps->MaximumFileSize = 100;		
	traceProps->BufferSize = 512;			
	traceProps->MaximumBuffers = 128;
	traceProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	traceProps->MinimumBuffers = 1;
	traceProps->FlushTimer = 1;
	traceProps->EnableFlags = EVENT_TRACE_FLAG_DISK_IO | EVENT_TRACE_FLAG_DISK_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT ;

	return traceProps;
}

void stopTrace(TRACEHANDLE hOpenedTrace, PEVENT_TRACE_PROPERTIES traceProps)
{
	if (hOpenedTrace)
	{
		ULONG result = ControlTrace(hOpenedTrace, NULL, traceProps, EVENT_TRACE_CONTROL_STOP);
		if (result != ERROR_SUCCESS)
		{
			wprintf(L"[-] StopTrace() failed:  %lu\n", result);
		}


		if (INVALID_PROCESSTRACE_HANDLE != hOpenedTrace)
		{
			result = CloseTrace(hOpenedTrace);
		}
	}
}


BOOL fileExists(WCHAR *strFile)
{
	DWORD       dwAttributes = GetFileAttributes(strFile);

	if (0xFFFFFFFF == dwAttributes) return FALSE;

	return TRUE;
}

HANDLE openFile(LPProcessTraceArguments traceArgs)
{

	if (traceArgs->hFile != NULL)
	{
		CloseHandle(traceArgs->hFile);

		SYSTEMTIME stime;
		GetSystemTime(&stime);
		WCHAR strNewFile[1024];
		wsprintf(strNewFile, L"%s_%d%d%d_%d%d%d.log", traceArgs->strOutputFile, stime.wYear, stime.wMonth, stime.wDay, stime.wHour, stime.wMinute, stime.wSecond);


		if (fileExists(strNewFile))
		{
			DeleteFile(strNewFile);
		}

		if (fileExists(traceArgs->strOutputFile))
		{
			MoveFile(traceArgs->strOutputFile, strNewFile);
		}
	}



	traceArgs->hFile = CreateFile(traceArgs->strOutputFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	return traceArgs->hFile;
}



VOID WINAPI CALLBACK_eventTrace(_In_ PEVENT_TRACE eventTrace)
{
	if (memcmp(&eventTrace->Header.Guid, &GUID_FILEIO, sizeof(GUID)) == 0)
	{

		// https://msdn.microsoft.com/en-us/library/windows/desktop/aa363776(v=vs.85).aspx
		// https://msdn.microsoft.com/en-us/library/windows/desktop/aa964768(v=vs.85).aspx
		// https://msdn.microsoft.com/en-us/library/windows/desktop/aa363885(v=vs.85).aspx
		if (eventTrace->Header.Class.Type == 64)
		{
			int fileNameSize = min(eventTrace->MofLength - sizeof(FILEIOCREATE) + 6, CURRENTWINMAXPATH);

			if (fileNameSize <= 0 || fileNameSize >= CURRENTWINMAXPATH) return;
			
			LPFILEIOCREATE fileData = (LPFILEIOCREATE)eventTrace->MofData;

			// Kolla upp ifall sökvägen finns i exkluderingslistan.
			for (int i = 0; i < excludePathsCount; i++)
			{
				if (excludePathsLengths[i] <  fileNameSize)
				{
					wchar_t *foundSubstring = wcsstr(fileData->strFilename, strExcludePaths[i]);

					if (foundSubstring != NULL) return;
				}

			}

			DWORD dwBytesWritten = 0;
			BOOL bErrorFlag = FALSE;
			WCHAR strFileTime[100];
			wsprintfW(strFileTime, L"%I64d|%d|%lu|", eventTrace->Header.TimeStamp.QuadPart, eventTrace->Header.Class.Type, eventTrace->Header.ProcessId);

			DWORD timeLen = (DWORD) wcsnlen_s(strFileTime, 100);

			bErrorFlag = WriteFile(traceArgs->hFile, strFileTime, timeLen * sizeof(WCHAR), &dwBytesWritten, NULL);
			dwAccumulatedBytes += dwBytesWritten;

			bErrorFlag = WriteFile(traceArgs->hFile, fileData->strFilename, fileNameSize ,&dwBytesWritten,NULL); 
			dwAccumulatedBytes += dwBytesWritten;

			bErrorFlag = WriteFile(traceArgs->hFile, STR_LINEFEED, 2 , &dwBytesWritten, NULL);
			dwAccumulatedBytes += dwBytesWritten;

			FlushFileBuffers(traceArgs->hFile);

			// Ifall vi uppnår en stor filstorlek så arkiverar vi den gamla filen och skriver en ny.
			if (dwAccumulatedBytes > dwMaxOutputSize)
			{
				traceArgs->hFile = openFile(traceArgs);
				dwAccumulatedBytes = 0;
			}

		}
	}
}


int __cdecl wmain(int argc, wchar_t *argv[])
{
	ULONG result =				ERROR_SUCCESS;
	TRACEHANDLE hSession =		NULL;
	TRACEHANDLE hOpenedTrace =	NULL;
	PWSTR LoggerName =			KERNEL_LOGGER_NAME; // Kernel logger
	PEVENT_TRACE_PROPERTIES		traceProps;
	HANDLE traceThread =		NULL;


	// Allokera minnet vi vill använda
	DWORD dwInitialSize = sizeof(ProcessTraceArguments) + sizeof(EVENT_TRACE_PROPERTIES);
	HANDLE hProgHeap = HeapCreate(0, 1024*256, dwInitialSize + 1024*512);

	traceArgs = (LPProcessTraceArguments) HeapAlloc(hProgHeap, 0, sizeof(ProcessTraceArguments));
	traceArgs->hFile = NULL;

	// Den vanliga argument-parsern
	for (int i = 0; i < argc; i++)
	{
		if (i < (argc + 1))
		{
			if (wcscmp(argv[i], L"--output") == 0)
			{
				i++;
				wcsncpy_s(traceArgs->strOutputFile, argv[i], 1024);
				//traceArgs->hFile = CreateFile(traceArgs->strOutputFile,GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
				traceArgs->hFile = openFile(traceArgs);
			}
			else if (wcscmp(argv[i], L"-e") == 0 && excludePathsCount < MAXEXCLUDEPATHS) // Exkludera
			{
				i++;
				int flen = (int) wcsnlen_s(argv[i], 1024);

				if (flen < 1024 && flen > 0)
				{
					excludePathsLengths[excludePathsCount] = (int) wcsnlen_s(argv[i], 1024);
					wcsncpy_s(strExcludePaths[excludePathsCount++], argv[i], flen);					
				}
			}
		}
	}

	if (traceArgs->hFile == NULL)
	{
		wprintf(L"[+] You'll need to specify output file with --output <file>\n");

		return -1;
	}

	// Ifall det uppstår fel med Heap så terminera.
	HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);

	// Skapa trace-struct.
	traceProps = createTraceProps(hProgHeap);

	if (traceProps == NULL)
	{
		wprintf(L"[-] Could not create trace properties\n");
		goto Exit;
	}

	// Starta igång trace
	result = StartTraceW(&hSession, LoggerName, traceProps);
	
	// Loggern är redan startad. Så vi startar om den.
	if (result == ERROR_ALREADY_EXISTS)
	{
		result = ControlTrace(0, LoggerName, traceProps, EVENT_TRACE_CONTROL_UPDATE);

		if (result != ERROR_SUCCESS)
		{
			wprintf(L"[-] Could not update trace \n");
			goto Exit;
		}
	}

	// TODO: Hantera detta fel om det uppstår.
	if (result == ERROR_SHARING_VIOLATION)
	{
		wprintf(L"[-] StartTrace() failed with %lu. Sharing violation.\n", result);
		goto Exit;
	}
	
	// Om vi inte kan hantera felet, så terminerar vi.
	if (result != ERROR_SUCCESS )
	{
		wprintf(L"[-] StartTrace() failed with %lu\n", result);
		goto Exit;
	}


	// Nu öppnar vi den trace som vi startade igång
	EVENT_TRACE_LOGFILE trace;
	ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
	trace.LoggerName =					(LPWSTR) LoggerName;
	trace.LogFileName =					(LPWSTR) NULL;
	trace.EventCallback =				CALLBACK_eventTrace;
	trace.ProcessTraceMode =			PROCESS_TRACE_MODE_REAL_TIME; // Notera denna.

	hOpenedTrace = OpenTrace(&trace);

	if (hOpenedTrace == INVALID_PROCESSTRACE_HANDLE)
	{
		DWORD err = GetLastError();
		wprintf(L"[-] PacketTraceSession: OpenTrace()  invalid_processtrace_handle %lu\n", err);	

		goto Exit;
	}



	wprintf(L"[+] ProcessTrace starts...\n");
	traceArgs->traceHandle = &hOpenedTrace;

	traceThread = startProcessTrace(traceArgs);

	wprintf(L"[+] Press key to exit\n");
	_getch();

	

Exit:

	wprintf(L"[+] Stopping trace...\n");

	// Stoppa tracevilket i sin tur kommer terminera tråden
	stopTrace(hOpenedTrace, traceProps);

	wprintf(L"[+] Waiting for thread to complete...\n");

	// Vänta på att process-tråden är klar. 

	if (traceThread != NULL)
	{
		WaitForSingleObject(traceThread, INFINITE);
	}


	if (traceArgs->hFile != NULL)
	{
		CloseHandle(traceArgs->hFile);
	}
	
	if (traceArgs != NULL)
	{
		HeapFree(hProgHeap, 0, traceArgs);
	}

	if (traceProps != NULL) 
	{
		HeapFree(hProgHeap, 0, traceProps);
	}

	wprintf(L"[+] Done!\n");

	return result;
}
