
#include <windows.h>

// 该结构体为CreateFile的地址和所需的参数
struct CREATEFILE_PARAM
{
	DWORD dwCreateAPIAddr;                //Createfile函数的地址
	LPCTSTR lpFileName;                    //下面都是CreateFile所需要用到的参数
	DWORD dwDesiredAccess;
	DWORD dwShareMode;
	LPSECURITY_ATTRIBUTES lpSecurityAttributes;
	DWORD dwCreationDisposition;
	DWORD dwFlagsAndAttributes;
	HANDLE hTemplateFile;
};

//定义一个函数指针
typedef HANDLE(WINAPI* PFN_CreateFile)
(	LPCTSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
);


//编写要复制到目标进程的函数
DWORD _stdcall ThreadProc_CreateFile(LPVOID lparam)
{
	CREATEFILE_PARAM* Gcreate = (CREATEFILE_PARAM*)lparam;
	PFN_CreateFile pfnCreateFile;
	pfnCreateFile = (PFN_CreateFile)Gcreate->dwCreateAPIAddr;	// 得到CreateFile函数的地址
	// 调用CreateFile
	pfnCreateFile(Gcreate->lpFileName, Gcreate->dwDesiredAccess, Gcreate->dwShareMode,Gcreate->lpSecurityAttributes, 
		Gcreate->dwCreationDisposition, Gcreate->dwFlagsAndAttributes,Gcreate->hTemplateFile);
	return 0;
}

//远程创建文件
BOOL RemoteCreateFile(DWORD dwProcessID, char* szFilePathName)
{
	BOOL bRet;
	DWORD dwThread;
	HANDLE hProcess;
	HANDLE hThread;
	DWORD dwThreadFunSize;
	CREATEFILE_PARAM GCreateFile;
	LPVOID lpFilePathName;
	LPVOID lpRemotThreadAddr;
	LPVOID lpFileParamAddr;
	DWORD dwFunAddr;
	HMODULE hModule;


	bRet = 0;
	hProcess = 0;
	dwThreadFunSize = 0x400;
	//1.获取进程的句柄
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	if (hProcess == NULL)
	{
		OutputDebugStringA("OpenProcessError!\n");
		return FALSE;
	}

	//2.分配3段内存：存储参数，线程函数，文件名
	//2.1 用来存储文件名
	lpFilePathName = VirtualAllocEx(hProcess, NULL, strlen(szFilePathName)+1, MEM_COMMIT, PAGE_READWRITE);
	//2.2 用来存储线程函数
	lpRemotThreadAddr = VirtualAllocEx(hProcess, NULL, dwThreadFunSize, MEM_COMMIT, PAGE_READWRITE);
	//2.3 用来存储文件参数
	lpFileParamAddr = VirtualAllocEx(hProcess, NULL, sizeof(CREATEFILE_PARAM), MEM_COMMIT, PAGE_READWRITE);

	//3. 初始化CreateFile参数
	GCreateFile.dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
	GCreateFile.dwShareMode = 0;
	GCreateFile.lpSecurityAttributes = NULL;
	GCreateFile.dwCreationDisposition = OPEN_ALWAYS;
	GCreateFile.dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
	GCreateFile.hTemplateFile = NULL;

	//4.获取CreateFile的地址
	hModule = GetModuleHandleA("kernel32.dll");
	GCreateFile.dwCreateAPIAddr = (DWORD)GetProcAddress(hModule, "CreateFileA");
	FreeLibrary(hModule);

	//5.初始化CreatFile文件名
	GCreateFile.lpFileName = (LPCTSTR)lpFilePathName;

	//6.获取线程函数起始地址
	dwFunAddr = (DWORD)ThreadProc_CreateFile;
	if (*((BYTE*)dwFunAddr) == 0xE9)	// 若为跳转
	{
		dwFunAddr = dwFunAddr + 5 + *(DWORD*)(dwFunAddr + 1);
	}

	//7.开始复制
	//7.1 拷贝文件名
	WriteProcessMemory(hProcess, lpFilePathName, szFilePathName, strlen(szFilePathName) + 1, 0);
	//7.2 拷贝线程函数
	WriteProcessMemory(hProcess, lpRemotThreadAddr, (LPVOID)dwFunAddr, dwThreadFunSize, 0);
	//7.3拷贝参数
	WriteProcessMemory(hProcess, lpFileParamAddr, &GCreateFile, sizeof(CREATEFILE_PARAM), 0);

	//8.创建远程线程
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpRemotThreadAddr, lpFileParamAddr, 0, &dwThread);//lpAllocAddr传给线程函数的参数.因为dll名字分配在内存中
	if (hThread == NULL)
	{
		OutputDebugStringA("CreateRemoteThread Error!\n");
		CloseHandle(hProcess);
		CloseHandle(hModule);
		return FALSE;
	}
	//9.关闭资源
	CloseHandle(hProcess);
	CloseHandle(hThread);
	CloseHandle(hModule);
	return TRUE;

}


int main()
{
	RemoteCreateFile(PID, "文件名");
	return 0;
}