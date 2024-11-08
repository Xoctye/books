# 1、开发环境
VS系列IDE：
设置兼容XP：属性-配置属性-常规-平台工具集
运行库设置：属性-C/C++-代码生成-运行库-多线程调式(/MTd)
MD：表示运行时库由操作系统提供一个DLL，程序里不集成。 
MT：表示运行时库由程序集成,程序不再需要操作系统提供运行时库DLL
MFC库相关：属性-配置属性-高级-MFC的使用-在静态库中使用MFC
ASLR：属性-链接器-高级-随机基址
PDB文件：属性-链接器-所有选项-生成调试信息
***
# 2、基础技术
#### 运行单一实例
```cpp
CreateMutex函数用于创建或打开一个命名或未命名的互斥体对象。

函数原型:
HANDLE CreateMutex(
    LPSECURITY_ATTRIBUTES lpMutexAttributes,  // 安全属性
    BOOL bInitialOwner,                      // 初始拥有者
    LPCTSTR lpName                           // 互斥体名称
);

参数说明:
- lpMutexAttributes: 指向SECURITY_ATTRIBUTES结构的指针,用于设置安全属性。NULL表示使用默认安全属性。
- bInitialOwner: 指定互斥体的初始所有权。TRUE表示创建线程立即拥有互斥体,FALSE表示不拥有。
- lpName: 互斥体的名称。NULL表示创建匿名互斥体。

返回值:
- 成功返回互斥体句柄
- 失败返回NULL
```
#### DLL延迟加载
属性-链接器-输入-延迟加载的DLL-XXX.dll;%(DelayLoadDLLs)
延迟加载的好处：在开发程序的时候,通常会使用第三方库。但是,并不是所有的第三方库都会提供静态库文件,大多数会提供动态库DLL文件；这样,程序需要相应的DLL文件才能加载启动。使用DLL延迟加载，当使用程序的时候,只需把exe文件发送给用户,而不需要附加DLL文件了,也不需要担心程序会丢失DLL文件。
#### 资源释放
```cpp
FindResource函数用于在指定模块中查找资源。

函数原型:
HRSRC FindResource(
    HMODULE hModule,      // 模块句柄
    LPCTSTR lpName,       // 资源名称
    LPCTSTR lpType        // 资源类型
);

参数说明:
- hModule: 包含资源的模块句柄。NULL表示使用当前模块。
- lpName: 要查找的资源名称。可以是字符串或资源ID。
- lpType: 资源类型。可以是预定义类型(如RT_BITMAP)或自定义类型。

返回值:
- 成功返回资源句柄HRSRC
- 失败返回NULL
```
```cpp
SizeOfResource函数用于获取指定资源的大小。

函数原型:
DWORD SizeOfResource(
    HMODULE hModule,  // 模块句柄
    HRSRC hResInfo    // 资源句柄
);

参数说明:
- hModule: 包含资源的模块句柄。NULL表示使用当前模块。
- hResInfo: 由FindResource函数返回的资源句柄。

返回值:
- 成功返回资源大小(字节数)
- 失败返回0
```
```cpp
LoadResource函数用于加载指定的资源到内存。

函数原型:
HGLOBAL LoadResource(
    HMODULE hModule,  // 模块句柄
    HRSRC hResInfo    // 资源句柄
);

参数说明:
- hModule: 包含资源的模块句柄。NULL表示使用当前模块。
- hResInfo: 由FindResource函数返回的资源句柄。

返回值:
- 成功返回指向资源数据的句柄
- 失败返回NULL
```
```cpp
LockResource函数用于获取资源数据的指针。

函数原型:
LPVOID LockResource(
    HGLOBAL hResData  // 资源数据句柄
);

参数说明:
- hResData: 由LoadResource函数返回的资源数据句柄。

返回值:
- 成功返回指向资源数据的指针
- 失败返回NULL
```
```cpp
BOOL FreeMyResource(UINT uiResouceName, char *lpszResourceType, char *lpszSaveFileName)
{
	// 获取指定模块里的指定资源
	HRSRC hRsrc = ::FindResource(NULL, MAKEINTRESOURCE(uiResouceName), lpszResourceType);
	if (NULL == hRsrc)
	{
		FreeRes_ShowError("FindResource");
		return FALSE;
	}
	// 获取资源的大小
	DWORD dwSize = ::SizeofResource(NULL, hRsrc);
	if (0 >= dwSize)
	{
		FreeRes_ShowError("SizeofResource");
		return FALSE;
	}
	// 将资源加载到内存里
	HGLOBAL hGlobal = ::LoadResource(NULL, hRsrc);
	if (NULL == hGlobal)
	{
		FreeRes_ShowError("LoadResource");
		return FALSE;
	}
	// 锁定资源
	LPVOID lpVoid = ::LockResource(hGlobal);
	if (NULL == lpVoid)
	{
		FreeRes_ShowError("LockResource");
		return FALSE;
	}

	// 保存资源为文件
	FILE *fp = NULL;
	fopen_s(&fp, lpszSaveFileName, "wb+");
	if (NULL == fp)
	{
		FreeRes_ShowError("LockResource");
		return FALSE;
	}
	fwrite(lpVoid, sizeof(char), dwSize, fp);
	fclose(fp);

	return TRUE;
}
```
# 3、注入技术
#### 全局钩子注入
```cpp
SetWindowsHookEx函数用于在系统中安装一个钩子过程,可以监视特定类型的事件。其函数原型如下:

HHOOK SetWindowsHookEx(
    int idHook,         // 钩子类型
    HOOKPROC lpfn,      // 钩子过程
    HINSTANCE hMod,     // DLL的句柄
    DWORD dwThreadId    // 线程ID
);

参数说明:
- idHook: 指定要安装的钩子类型,如WH_KEYBOARD(键盘)、WH_MOUSE(鼠标)等
- lpfn: 指向钩子过程的指针
- hMod: 包含钩子过程的DLL句柄
- dwThreadId: 与钩子关联的线程ID,为0则钩子与所有线程关联

返回值:
- 成功返回钩子句柄
- 失败返回NULL

注意:安装钩子需要管理员权限,使用完需要通过UnhookWindowsHookEx卸载钩子。
```
```cpp
//共享内存
ipragma data_seg("mydata")
#pragma data_seg() HHOOK g_hHook = NULL;
#pragma comment (linker,"/SECTION:mydata,RWS")
```
#### 远程线程注入
```cpp
OpenProcess函数用于打开一个已存在的进程对象,获取进程句柄。其函数原型如下:

HANDLE OpenProcess(
    DWORD dwDesiredAccess,    // 访问权限
    BOOL bInheritHandle,      // 是否可继承
    DWORD dwProcessId         // 进程ID
);

参数说明:
- dwDesiredAccess: 指定进程的访问权限,如PROCESS_ALL_ACCESS表示所有权限
- bInheritHandle: 指定返回的句柄是否可以被子进程继承
- dwProcessId: 要打开的进程ID

返回值:
- 成功返回进程句柄
- 失败返回NULL

常用访问权限:
- PROCESS_ALL_ACCESS: 完全访问权限
- PROCESS_CREATE_THREAD: 创建线程权限
- PROCESS_VM_OPERATION: 执行操作权限
- PROCESS_VM_READ: 读取内存权限
- PROCESS_VM_WRITE: 写入内存权限

注意:打开进程需要相应权限,使用完需要通过CloseHandle关闭句柄。
```
```cpp
VirtualAllocEx函数用于在指定进程的虚拟地址空间中分配内存。其函数原型如下:

LPVOID VirtualAllocEx(
    HANDLE hProcess,          // 进程句柄
    LPVOID lpAddress,        // 内存地址
    SIZE_T dwSize,           // 内存大小
    DWORD flAllocationType,  // 分配类型
    DWORD flProtect          // 内存保护属性
);

参数说明:
- hProcess: 目标进程的句柄
- lpAddress: 指定分配的内存地址,NULL表示由系统选择
- dwSize: 要分配的内存大小(字节)
- flAllocationType: 内存分配类型,如MEM_COMMIT、MEM_RESERVE等
- flProtect: 内存保护属性,如PAGE_EXECUTE_READWRITE等

返回值:
- 成功返回分配的内存地址
- 失败返回NULL

常用内存保护属性:
- PAGE_EXECUTE: 可执行
- PAGE_EXECUTE_READ: 可执行和读取
- PAGE_EXECUTE_READWRITE: 可执行、读取和写入
- PAGE_READONLY: 只读
- PAGE_READWRITE: 可读写

注意:分配的内存需要通过VirtualFreeEx释放。

```
```cpp
WriteProcessMemory函数用于将数据写入到指定进程的内存空间。其函数原型如下:

BOOL WriteProcessMemory(
    HANDLE hProcess,                // 目标进程句柄
    LPVOID lpBaseAddress,          // 写入的内存地址
    LPCVOID lpBuffer,              // 要写入的数据缓冲区
    SIZE_T nSize,                  // 要写入的字节数
    SIZE_T *lpNumberOfBytesWritten // 实际写入的字节数
);

参数说明:
- hProcess: 目标进程的句柄
- lpBaseAddress: 要写入数据的内存地址
- lpBuffer: 包含要写入数据的缓冲区
- nSize: 要写入的字节数
- lpNumberOfBytesWritten: 返回实际写入的字节数,可为NULL

返回值:
- 成功返回TRUE
- 失败返回FALSE

注意事项:
- 写入地址必须具有写入权限
- 写入的内存地址必须是已分配的
- 写入的数据大小不能超过目标内存区域大小
- 需要确保目标进程句柄具有PROCESS_VM_WRITE权限
```
```cpp
CreateRemoteThread函数用于在远程进程中创建线程。其函数原型如下:

HANDLE CreateRemoteThread(
    HANDLE hProcess,               // 目标进程句柄
    LPSECURITY_ATTRIBUTES lpThreadAttributes, // 线程安全属性
    SIZE_T dwStackSize,           // 线程栈大小
    LPTHREAD_START_ROUTINE lpStartAddress,  // 线程函数地址
    LPVOID lpParameter,           // 传递给线程函数的参数
    DWORD dwCreationFlags,        // 线程创建标志
    LPDWORD lpThreadId            // 返回线程ID
);

参数说明:
- hProcess: 目标进程的句柄
- lpThreadAttributes: 线程安全属性,通常为NULL
- dwStackSize: 线程栈大小,0表示使用默认大小
- lpStartAddress: 线程函数的地址
- lpParameter: 传递给线程函数的参数
- dwCreationFlags: 控制线程创建的标志
- lpThreadId: 用于接收新创建线程的ID,可为NULL

返回值:
- 成功返回线程句柄
- 失败返回NULL

注意事项:
- 需要确保目标进程句柄具有PROCESS_CREATE_THREAD权限
- 线程函数必须存在于目标进程的地址空间中
- 创建的远程线程执行完毕后需要关闭线程句柄
- 常用于注入DLL到目标进程
```
远程线程原理：
从声明中可以知道,CreatecRemoteThread 需要传递的是目标进程空间中的多线程函数地址, 以及多线程参数,其中参数类型是空指针类型。接下来,将上述两个函数声明结合起来思考。可以大胆设想一下,如果程序能够获取目标进程LoadLibrary函数的地址,而且还能够获取目标进程空间中某个DLL路径字符串的地址, 那么,可将LoadLibrary函数的地址作为多线程函数的地址,某个DLL路径字符申作为多线程 函数的参数,并传递给CreateRemoteThread函数在目标进程空间中创建一个多线程,这样能不 能成功呢?答案是可以的。这样,就可以在目标进程空间中创建一个多线程,这个多线程就是 LoadLibrary函数加载DLL。
```cpp

// 使用 CreateRemoteThread 实现远程线程注入
BOOL CreateRemoteThreadInjectDll(DWORD dwProcessId, char *pszDllFileName)
{
	HANDLE hProcess = NULL;
	SIZE_T dwSize = 0;
	LPVOID pDllAddr = NULL;
	FARPROC pFuncProcAddr = NULL;

	// 打开注入进程，获取进程句柄
	hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (NULL == hProcess)
	{
		ShowError("OpenProcess");
		return FALSE;
	}
	// 在注入进程中申请内存
	dwSize = 1 + ::lstrlen(pszDllFileName);
	pDllAddr = ::VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (NULL == pDllAddr)
	{
		ShowError("VirtualAllocEx");
		return FALSE;
	}
	// 向申请的内存中写入数据
	if (FALSE == ::WriteProcessMemory(hProcess, pDllAddr, pszDllFileName, dwSize, NULL))
	{
		ShowError("WriteProcessMemory");
		return FALSE;
	}
	// 获取LoadLibraryA函数地址
	pFuncProcAddr = ::GetProcAddress(::GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (NULL == pFuncProcAddr)
	{
		ShowError("GetProcAddress_LoadLibraryA");
		return FALSE;
	}
	// 使用 CreateRemoteThread 创建远线程, 实现 DLL 注入
	HANDLE hRemoteThread = ::CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFuncProcAddr, pDllAddr, 0, NULL);
	if (NULL == hRemoteThread)
	{
		ShowError("CreateRemoteThread");
		return FALSE;
	}
	// 关闭句柄
	::CloseHandle(hProcess);

	return TRUE;
}
```
#### 突破Session 0隔离的远程线程注入
```cpp

// 使用 ZwCreateThreadEx 实现远线程注入
BOOL ZwCreateThreadExInjectDll(DWORD dwProcessId, char *pszDllFileName)
{
	HANDLE hProcess = NULL;
	SIZE_T dwSize = 0;
	LPVOID pDllAddr = NULL;
	FARPROC pFuncProcAddr = NULL;
	HANDLE hRemoteThread = NULL;
	DWORD dwStatus = 0;

	// 打开注入进程，获取进程句柄
	hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (NULL == hProcess)
	{
		ShowError("OpenProcess");
		return FALSE;
	}
	// 在注入进程中申请内存
	dwSize = 1 + ::lstrlen(pszDllFileName);
	pDllAddr = ::VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (NULL == pDllAddr)
	{
		ShowError("VirtualAllocEx");
		return FALSE;
	}
	// 向申请的内存中写入数据
	if (FALSE == ::WriteProcessMemory(hProcess, pDllAddr, pszDllFileName, dwSize, NULL))
	{
		ShowError("WriteProcessMemory");
		return FALSE;
	}
	// 加载 ntdll.dll
	HMODULE hNtdllDll = ::LoadLibrary("ntdll.dll");
	if (NULL == hNtdllDll)
	{
		ShowError("LoadLirbary");
		return FALSE;
	}
	// 获取LoadLibraryA函数地址
	pFuncProcAddr = ::GetProcAddress(::GetModuleHandle("Kernel32.dll"), "LoadLibraryA");
	if (NULL == pFuncProcAddr)
	{
		ShowError("GetProcAddress_LoadLibraryA");
		return FALSE;
	}
	// 获取ZwCreateThread函数地址
#ifdef _WIN64
	typedef DWORD(WINAPI *typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		ULONG CreateThreadFlags,
		SIZE_T ZeroBits,
		SIZE_T StackSize,
		SIZE_T MaximumStackSize,
		LPVOID pUnkown);
#else
	typedef DWORD(WINAPI *typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		BOOL CreateSuspended,
		DWORD dwStackSize,
		DWORD dw1,
		DWORD dw2,
		LPVOID pUnkown);
#endif
	typedef_ZwCreateThreadEx ZwCreateThreadEx = (typedef_ZwCreateThreadEx)::GetProcAddress(hNtdllDll, "ZwCreateThreadEx");
	if (NULL == ZwCreateThreadEx)
	{
		ShowError("GetProcAddress_ZwCreateThread");
		return FALSE;
	}
	// 使用 ZwCreateThreadEx 创建远线程, 实现 DLL 注入
	dwStatus = ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pFuncProcAddr, pDllAddr, 0, 0, 0, 0, NULL);
	if (NULL == hRemoteThread)
	{
		ShowError("ZwCreateThreadEx");
		return FALSE;
	}
	// 关闭句柄
	::CloseHandle(hProcess);
	::FreeLibrary(hNtdllDll);

	return TRUE;
}
```
```cpp

BOOL EnbalePrivileges(HANDLE hProcess, char *pszPrivilegesName)
{
	HANDLE hToken = NULL;
	LUID luidValue = {0};
	TOKEN_PRIVILEGES tokenPrivileges = {0};
	BOOL bRet = FALSE;
	DWORD dwRet = 0;


	// 打开进程令牌并获取具有 TOKEN_ADJUST_PRIVILEGES 权限的进程令牌句柄
	bRet = ::OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (FALSE == bRet)
	{
		EP_ShowError("OpenProcessToken");
		return FALSE;
	}
	// 获取本地系统的 pszPrivilegesName 特权的LUID值
	bRet = ::LookupPrivilegeValue(NULL, pszPrivilegesName, &luidValue);
	if (FALSE == bRet)
	{
		EP_ShowError("LookupPrivilegeValue");
		return FALSE;
	}
	// 设置提升权限信息
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	// 提升进程令牌访问权限
	bRet = ::AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, NULL, NULL);
	if (FALSE == bRet)
	{
		EP_ShowError("AdjustTokenPrivileges");
		return FALSE;
	}
	else
	{
		// 根据错误码判断是否特权都设置成功
		dwRet = ::GetLastError();
		if (ERROR_SUCCESS == dwRet)
		{
			return TRUE;
		}
		else if (ERROR_NOT_ALL_ASSIGNED == dwRet)
		{
			EP_ShowError("ERROR_NOT_ALL_ASSIGNED");
			return FALSE;
		}
	}

	return FALSE;
}
```
#### APC注入
实现APC注入的具体流程如下：
首先,通过OpenProccss函数打开目标进程,获取目标进程的句柄。
然后,通过调用WIN32 API函数CreateToolhelp32Snapshot、Thread32First以及Thread32Next遍历线程快照,获取目标进程的所有线程ID。
接着,调用VirtualAllocEx函数在目标进程中申请内存,并通过WriteProcessMemory函数向内存中写入DLL的注入路径。
最后,遍历获取的线程ID,并调用OpenThread函数以THREAD ALL ACCESS访问权限 打开线程,获取线程句柄。并调用QueulUerAPC函数向线程插入APC函数,设置APC函数 的地址为LoadLibraryA函数的地址,并设置APC函数参数为上述DLL路径地址。
```cpp

// APC注入
BOOL ApcInjectDll(char *pszProcessName, char *pszDllName)
{
	BOOL bRet = FALSE;
	DWORD dwProcessId = 0;
	DWORD *pThreadId = NULL;
	DWORD dwThreadIdLength = 0;
	HANDLE hProcess = NULL, hThread = NULL;
	PVOID pBaseAddress = NULL;
	PVOID pLoadLibraryAFunc = NULL;
	SIZE_T dwRet = 0, dwDllPathLen = 1 + ::lstrlen(pszDllName);
	DWORD i = 0;

	do
	{
		// 根据进程名称获取PID
		dwProcessId = GetProcessIdByProcessName(pszProcessName);
		if (0 >= dwProcessId)
		{
			bRet = FALSE;
			break;
		}

		// 根据PID获取所有的相应线程ID
		bRet = GetAllThreadIdByProcessId(dwProcessId, &pThreadId, &dwThreadIdLength);
		if (FALSE == bRet)
		{
			bRet = FALSE;
			break;
		}

		// 打开注入进程
		hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (NULL == hProcess)
		{
			ShowError("OpenProcess");
			bRet = FALSE;
			break;
		}

		// 在注入进程空间申请内存
		pBaseAddress = ::VirtualAllocEx(hProcess, NULL, dwDllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NULL == pBaseAddress)
		{
			ShowError("VirtualAllocEx");
			bRet = FALSE;
			break;
		}
		// 向申请的空间中写入DLL路径数据 
		::WriteProcessMemory(hProcess, pBaseAddress, pszDllName, dwDllPathLen, &dwRet);
		if (dwRet != dwDllPathLen)
		{
			ShowError("WriteProcessMemory");
			bRet = FALSE;
			break;
		}

		// 获取 LoadLibrary 地址
		pLoadLibraryAFunc = ::GetProcAddress(::GetModuleHandle("kernel32.dll"), "LoadLibraryA");
		if (NULL == pLoadLibraryAFunc)
		{
			ShowError("GetProcessAddress");
			bRet = FALSE;
			break;
		}

		// 遍历线程, 插入APC
		for (i = 0; i < dwThreadIdLength; i++)
		{
			// 打开线程
			hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, pThreadId[i]);
			if (hThread)
			{
				// 插入APC
				::QueueUserAPC((PAPCFUNC)pLoadLibraryAFunc, hThread, (ULONG_PTR)pBaseAddress);
				// 关闭线程句柄
				::CloseHandle(hThread);
				hThread = NULL;
			}
		}

		bRet = TRUE;

	} while (FALSE);

	// 释放内存
	if (hProcess)
	{
		::CloseHandle(hProcess);
		hProcess = NULL;
	}
	if (pThreadId)
	{
		delete[]pThreadId;
		pThreadId = NULL;
	}

	return bRet;
}
```
***
# 4、启动技术
#### 创建进程API
| 函数名 | WinExec | ShellExecute | CreateProcess |
|--------|---------|--------------|---------------|
| 头文件 | windows.h | shellapi.h | windows.h |
| 函数原型 | UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow) | HINSTANCE ShellExecute(HWND hwnd, LPCTSTR lpOperation, LPCTSTR lpFile, LPCTSTR lpParameters, LPCTSTR lpDirectory, INT nShowCmd) | BOOL CreateProcess(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) |
| 功能特点 | - 最简单的进程创建函数<br>- 只能运行16位Windows程序<br>- 已过时，不推荐使用 | - 可执行文件、文档等多种类型<br>- 会调用关联程序打开文档<br>- 支持动作(open/print等) | - 功能最强大完整<br>- 可详细控制进程创建<br>- 可获取进程、线程句柄 |
| 参数控制 | 较少，仅命令行和显示方式 | 中等，支持操作类型和工作目录 | 最多，支持安全特性、环境变量等 |
| 返回值 | 返回值>31表示成功 | 返回值>32表示成功 | TRUE表示成功 |
| 使用场景 | 简单的程序启动(不推荐) | 调用关联程序打开文档 | 需要精确控制的进程创建 |
#### 突破SESSION 0隔离创建用户进程
```cpp
// 突破SESSION 0隔离创建用户进程
BOOL CreateUserProcess(char *lpszFileName)
{
	BOOL bRet = TRUE;
	DWORD dwSessionID = 0;
	HANDLE hToken = NULL;
	HANDLE hDuplicatedToken = NULL;
	LPVOID lpEnvironment = NULL;
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);

	do
	{
		// 获得当前Session ID
		dwSessionID = ::WTSGetActiveConsoleSessionId();

		// 获得当前Session的用户令牌
		if (FALSE == ::WTSQueryUserToken(dwSessionID, &hToken))
		{
			ShowMessage("WTSQueryUserToken", "ERROR");
			bRet = FALSE;
			break;
		}

		// 复制令牌
		if (FALSE == ::DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
			SecurityIdentification, TokenPrimary, &hDuplicatedToken))
		{
			ShowMessage("DuplicateTokenEx", "ERROR");
			bRet = FALSE;
			break;
		}

		// 创建用户Session环境
		if (FALSE == ::CreateEnvironmentBlock(&lpEnvironment,
			hDuplicatedToken, FALSE))
		{
			ShowMessage("CreateEnvironmentBlock", "ERROR");
			bRet = FALSE;
			break;
		}

		// 在复制的用户Session下执行应用程序，创建进程
		if (FALSE == ::CreateProcessAsUser(hDuplicatedToken,
			lpszFileName, NULL, NULL, NULL, FALSE,
			NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
			lpEnvironment, NULL, &si, &pi))
		{
			ShowMessage("CreateProcessAsUser", "ERROR");
			bRet = FALSE;
			break;
		}

	} while (FALSE);
	// 关闭句柄, 释放资源
	if (lpEnvironment)
	{
		::DestroyEnvironmentBlock(lpEnvironment);
	}
	if (hDuplicatedToken)
	{
		::CloseHandle(hDuplicatedToken);
	}
	if (hToken)
	{
		::CloseHandle(hToken);
	}
	return bRet;
}
```
```cpp
//创建服务示例
#include <windows.h>
#include <stdio.h>
#include <tchar.h>

// 服务名称
#define SERVICE_NAME _T("MySampleService")
// 日志文件路径
#define LOG_FILE_PATH _T("C:\\MyServiceLog.log")

// 服务状态变量
SERVICE_STATUS ServiceStatus;
// 服务状态句柄
SERVICE_STATUS_HANDLE ServiceStatusHandle;

// 服务控制处理函数
VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
    switch (CtrlCode)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
        break;
    default:
        break;
    }
}

// 服务主函数
VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    // 注册服务控制处理函数
    ServiceStatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);

    // 初始化服务状态
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_STARTING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    // 设置服务状态
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

    // 打开日志文件
    HANDLE hLogFile = CreateFile(LOG_FILE_PATH, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hLogFile == INVALID_HANDLE_VALUE)
    {
        // 如果打开失败，记录错误并停止服务
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
        return;
    }

    // 服务主循环
    while (ServiceStatus.dwCurrentState == SERVICE_STARTING)
    {
        // 记录信息到日志文件
        TCHAR logMessage[] = _T("Service is running. Log entry at: ");
        SYSTEMTIME st;
        GetSystemTime(&st);
        _stprintf_s(logMessage + _tcslen(logMessage), sizeof(logMessage) - _tcslen(logMessage),
                    _T("%02d:%02d:%02d\n"), st.hour, st.minute, st.second);
        DWORD bytesWritten;
        WriteFile(hLogFile, logMessage, _tcslen(logMessage) * sizeof(TCHAR), &bytesWritten, NULL);

        // 等待一段时间，这里设置为每隔10秒记录一次
        Sleep(10000);

        // 更新服务状态检查点
        ServiceStatus.dwCheckPoint++;
    }

    // 关闭日志文件
    CloseHandle(hLogFile);

    // 服务停止后设置状态
    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
}

// 安装服务函数
BOOL InstallService()
{
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager == NULL)
    {
        return FALSE;
    }

    SC_HANDLE schService = CreateService(schSCManager, SERVICE_NAME, SERVICE_NAME,
                                         SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                         SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                         NULL, NULL, NULL, NULL, NULL);
    if (schService == NULL)
    {
        CloseHandle(schSCManager);
        return FALSE;
    }

    CloseHandle(schService);
    CloseHandle(schSCManager);
    return TRUE;
}

// 卸载服务函数
BOOL UninstallService()
{
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager == NULL)
    {
        return FALSE;
    }

    SC_HANDLE schService = OpenService(schSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (schService == NULL)
    {
        CloseHandle(schSCManager);
        return FALSE;
    }

    if (!DeleteService(schService))
    {
        CloseHandle(schService);
        CloseHandle(schSCManager);
        return FALSE;
    }

    CloseHandle(schService);
    CloseHandle(schSCManager);
    return TRUE;
}

int main(int argc, char* argv[])
{
    if (argc > 1)
    {
        if (_tcsicmp(argv[1], _T("install")) == 0)
        {
            if (InstallService())
            {
                _tprintf(_T("Service installed successfully.\n"));
            }
            else
            {
                _tprintf(_T("Failed to install service. Error: %d\n"), GetLastError());
            }
        }
        else if (_tcsicmp(argv[1], _T("uninstall")) == 0)
        {
            if (UninstallService())
            {
                _tprintf(_T("Service uninstalled successfully.\n"));
            }
            else
            {
                _tprintf(_T("Failed to uninstall service. Error: %d\n"), GetLastError());
            }
        }
        else
        {
            _tprintf(_T("Invalid argument. Use 'install' or 'uninstall'.\n"));
        }
    }
    else
    {
        // 启动服务逻辑
        SERVICE_TABLE_ENTRY ServiceTable[] =
        {
            { SERVICE_NAME, ServiceMain },
            { NULL, NULL }
        };

        if (!StartServiceCtrlDispatcher(ServiceTable))
        {
            _tprintf(_T("Failed to start service control dispatcher. Error: %d\n"), GetLastError());
        }
    }

    return 0;
}
```
#### 内存直接加载运行
```cpp
首先，在DLL文件中，根据PE结构获取其加载映像的大小SizeOfImage，并根据SizeOfImage在自己的程序中申请可读、可写、可执行的内存，那么这块内存的首地址就是DLL的加载基址。

其次，根据DLL中的PE结构获取其映像对齐大小SectionAlignment，然后把DLL文件数据按照SectionAlignment复制到上述申请的可读、可写、可执行的内存中。

接下来，根据PE结构的重定位表，重新对重定位表进行修正。

然后，根据PE结构的导入表，加载所需的DLL，并获取导入函数的地址并写入导入表中。

接着，修改DLL的加载基址ImageBase。

最后，根据PE结构获取DLL的入口地址，然后构造并调用DllMain函数，实现DLL加载。

而exe文件相对于DLL文件实现原理唯一的区别就在于构造入口函数的差别，exe不需要构造DllMain函数，而是根据PE结构获取exe的入口地址偏移AddressOfEntryPoint并计算出入口地址，然后直接跳转到入口地址处执行即可。

要特别注意的是，对于exe文件来说，重定位表不是必需的，即使没有重定位表，exe也可正常运行。因为对于exe进程来说，进程最早加载的模块是exe模块，所以它可以按照默认的加载基址加载到内存。对于那些没有重定位表的程序，只能把它加载到默认的加载基址上。如果默认加载基址已被占用，则直接内存加载运行会失败。
```
***
# 5、自启动技术
#### 注册表
向以下注册表路径添加程序路径：

- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run

注意：在64位系统中存在注册表重定位
#### 快速启动目录
快速启动目录并不是一个固定目录，每台计算机的快速启动目录都不相同。但是程序可以使用SHGetSpecialFolderPath函数获取Windows系统中快速启动目录的路径，快速启动目录的CSIDL标识值为CSIDL_STARTUP。
```cpp
SHGetSpecialFolderPath函数用于获取Windows系统中特殊文件夹的路径。其函数原型如下:

BOOL SHGetSpecialFolderPath(
    HWND hwndOwner,      // 父窗口句柄,可以为NULL
    LPTSTR lpszPath,     // 接收路径的缓冲区
    int csidl,           // 特殊文件夹的CSIDL值
    BOOL fCreate         // 如果文件夹不存在是否创建
);

参数说明:
- hwndOwner: 父窗口句柄,通常设为NULL
- lpszPath: 用于接收特殊文件夹完整路径的缓冲区
- csidl: 特殊文件夹的标识符,如CSIDL_STARTUP表示快速启动目录
- fCreate: 如果指定的文件夹不存在,TRUE表示创建该文件夹,FALSE表示不创建

函数返回值:
- 成功返回TRUE
- 失败返回FALSE
```
```cpp
// AutoRun_Startup_Test.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <Shlobj.h>
#pragma comment(lib, "shell32.lib")


BOOL AutoRun_Startup(char *lpszSrcFilePath, char *lpszDestFileName)
{
	BOOL bRet = FALSE;
	char szStartupPath[MAX_PATH] = {0};
	char szDestFilePath[MAX_PATH] = {0};
	// 获取 快速启动目录 路径
	bRet = ::SHGetSpecialFolderPath(NULL, szStartupPath, CSIDL_STARTUP, TRUE);
	printf("szStartupPath=%s\n", szStartupPath);
	if (FALSE == bRet)
	{
		return FALSE;
	}
	// 构造拷贝的 目的文件路径
	::wsprintf(szDestFilePath, "%s\\%s", szStartupPath, lpszDestFileName);
	// 拷贝文件到快速启动目录下
	bRet = ::CopyFile(lpszSrcFilePath, szDestFilePath, FALSE);
	if (FALSE == bRet)
	{
		return FALSE;
	}

	return TRUE;
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (FALSE == AutoRun_Startup("C:\\Users\\HR\\Desktop\\A.exe","A.exe"))
	{
		printf("Startup Error!\n");
	}
	printf("Startup OK!\n");

	system("pause");
	return 0;
}
```
#### 计划任务
1. 初始化操作
- 调用 CoInitialize 初始化COM环境
- 调用 CoCreateInstance 创建任务计划服务实例
- 调用 ITaskService::Connect 连接任务计划服务
- 调用 ITaskService::GetFolder 获取根任务文件夹
- 获取 ITaskFolder 对象指针

2. 创建任务计划操作
- 调用 ITaskFolder::CreateTask 创建任务定义对象
- 设置任务基本信息(名称、描述等)
- 设置任务触发器(启动时间、重复间隔等)
- 设置任务操作(要执行的程序路径、参数等) 
- 设置任务权限和运行级别
- 调用 ITaskFolder::RegisterTaskDefinition 注册任务计划

3. 删除任务计划操作
- 调用 ITaskFolder::DeleteTask 删除指定名称的任务
- 检查删除结果

注意事项:
- 编程实现需要管理员权限
- 记得释放COM接口指针
- 调用 CoUninitialize 释放COM环境
- 需要包含 taskschd.h 头文件
- 需要链接 taskschd.lib 库
#### 系统服务
1. 创建和启动系统服务
- 调用 OpenSCManager 连接服务控制管理器
- 调用 CreateService 创建新服务
  - 设置服务名称、显示名称、启动类型等
  - 指定服务程序路径
  - 设置服务账户和权限
- 调用 OpenService 打开已存在服务
- 调用 StartService 启动服务
- 调用 DeleteService 删除服务
- 关闭服务和服务管理器句柄

2. 编写系统服务程序
- 创建服务入口点函数 ServiceMain
  - 注册服务控制处理函数
  - 设置服务状态
  - 执行服务初始化
  - 实现服务主要功能
- 创建服务控制处理函数
  - 处理 SERVICE_CONTROL_STOP 等控制请求
  - 更新服务状态
- 调用 StartServiceCtrlDispatcher 连接到服务控制管理器

注意事项:
- 需要管理员权限运行
- 服务程序必须是独立的可执行文件
- 正确处理服务状态变化
- 实现优雅的启动和停止流程
- 添加错误处理和日志记录
***
# 6、提权技术
#### 进程访问令牌权限提升
通过以下步骤实现进程访问令牌权限提升:
- 调用 OpenProcessToken 获取进程访问令牌
- 调用 LookupPrivilegeValue 根据权限名称获取 LUID 值 
- 调用 AdjustTokenPrivileges 设置新特权并修改进程令牌特权
- 使用 GetLastError 判断特权设置是否成功
#### Bypass UAC
1. 基于白名单程序（如 CompMgmtLauncher.exe），通过修改注册表（HKCU\Software\Classes\mscfiles\shell\open\command）启动目标程序实现提权。
2. 基于 COM 组件接口技术（利用 ICMLuaUtil 接口的 ShellExec 方法），通过 COM 提升名称提权。
***
# 7、隐藏技术
#### 进程伪装
```cpp
#include "DisguiseProcess.h"

void ShowError(char* pszText)
{
	char szErr[MAX_PATH] = { 0 };
	::wsprintf(szErr, "%s Error[%d]\n", pszText, ::GetLastError());
	::MessageBox(NULL, szErr, "ERROR", MB_OK);
}

// 修改指定进程的PEB中的路径和命令行信息以实现伪装
BOOL DisguiseProcess(DWORD dwProcessId, wchar_t* lpwszPath, wchar_t* lpwszCmd)
{
	// 打开目标进程以获取其句柄
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (NULL == hProcess)
	{
		ShowError("OpenProcess");
		return FALSE;
	}

	typedef_NtQueryInformationProcess NtQueryInformationProcess = NULL;
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	PEB peb = { 0 };
	RTL_USER_PROCESS_PARAMETERS Param = { 0 };
	USHORT usCmdLen = 0;
	USHORT usPathLen = 0;
	// 从 ntdll.dll 中获取 NtQueryInformationProcess 函数地址
	NtQueryInformationProcess = (typedef_NtQueryInformationProcess)::GetProcAddress(
		::LoadLibrary("ntdll.dll"), "NtQueryInformationProcess");
	if (NULL == NtQueryInformationProcess)
	{
		ShowError("GetProcAddress");
		return FALSE;
	}
	// 获取目标进程的基本信息
	NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	if (!NT_SUCCESS(status))
	{
		ShowError("NtQueryInformationProcess");
		return FALSE;
	}

	/*
		在读写其他进程时，必须使用 ReadProcessMemory/WriteProcessMemory。
		指针只能指向当前进程的地址空间，因此需要读取到当前进程空间。
		否则会提示非法访问错误。
	*/
	// 获取目标进程的 PebBaseAddress
	ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
	// 获取目标进程的 ProcessParameters，注意指针指向的是目标进程空间
	ReadProcessMemory(hProcess, peb.ProcessParameters, &Param, sizeof(Param), NULL);

	// 修改目标进程的命令行信息，注意指针指向的是目标进程空间
	usCmdLen = 2 + 2 * wcslen(lpwszCmd);
	WriteProcessMemory(hProcess, Param.CommandLine.Buffer, lpwszCmd, usCmdLen, NULL);
	::WriteProcessMemory(hProcess, &Param.CommandLine.Length, &usCmdLen, sizeof(usCmdLen), NULL);
	// 修改目标进程的路径信息，注意指针指向的是目标进程空间
	usPathLen = 2 + 2 * wcslen(lpwszPath);
	WriteProcessMemory(hProcess, Param.ImagePathName.Buffer, lpwszPath, usPathLen, NULL);
	WriteProcessMemory(hProcess, &Param.ImagePathName.Length, &usPathLen, sizeof(usPathLen), NULL);

	return TRUE;
}
```
#### 傀儡进程
傀儡进程的基本思想是创建一个合法的进程，然后将其内部的代码替换为恶意代码，从而使恶意代码在合法进程的上下文中运行。

傀儡进程的实现步骤通常如下：
1. 创建一个合法的进程（通常是一个系统进程，如svchost.exe）。
2. 暂停该进程的执行。
3. 使用NtUnmapViewOfSection函数卸载该进程的可执行映像。
4. 将恶意代码映像写入该进程的地址空间。
5. 修改进程的入口点，使其指向恶意代码的入口点。
6. 恢复进程的执行，使其开始执行恶意代码。

通过这种方式，攻击者可以隐藏恶意代码的执行，并利用合法进程的权限和上下文来进行恶意活动。傀儡进程技术常用于高级持久性威胁（APT）和其他复杂的攻击中。
#### 进程隐藏
采用 HOOK API 函数ZwQuerySystemInformation，在其内部判断并修改返回的进程信息，从而隐藏指定进程。
#### DLL劫持
利用 Windows 加载器搜索 DLL 的路径顺序，伪造同名 DLL 并转发或调用原 DLL 导出函数，实现劫持。
***
# 8、压缩技术
#### 数据压缩API
数据压缩
数据压缩主要是通过调用RtlCompressBuffer函数来实现的，具体的数据压缩流程如下：
首先，调用LoadLibrary函数加载ntdll.dll，并获取ntdll.dll加载模块的句柄。再调用GetProcAddress函数来获取RtlGetCompressionWorkSpaceSize函数以及RtlCompressBuffer函数。

然后，直接调用RtlGetCompressionWorkSpaceSize函数来获取RtlCompressBuffer函数的工作空间缓冲区的大小。其中，压缩格式和引擎类型设置为COMPRESSION_FORMAT_LZNT1和COMPRESSION_ENGINE_STANDARD。然后，根据工作空间缓冲区的大小申请一个工作空间缓冲区给压缩数据来使用。

最后，调用RtlCompressBuffer函数来压缩数据。数据压缩缓冲区的大小为4096字节，在成功压缩数据之后，便会获取实际的压缩数据大小。

数据解压缩
首先，调用LoadLibrary函数加载ntdll.dll，并获取ntdll.dll加载模块的句柄。再调用GetProcAddress函数来获取RtlDecompressBuffer函数。不需要获取RtlGetCompressionWorkSpaceSize函数的地址，因为数据解压缩操作不需要确定压缩工作空间缓冲区的大小。

然后，开始调用RtlDecompressBuffer函数来解压缩数据。
#### ZLIB库
https://www.cnblogs.com/castor-xu/p/14786489.html
***
# 9、加密技术
#### windows自带的加密库
```cpp
//HASH
// 计算文件的HASH值
BOOL CalcFileHash(LPCWSTR lpFileName, ALG_ID algId, BYTE* pbHash, DWORD* pdwHashLen) 
{
    BOOL bRet = FALSE;
    HANDLE hFile = NULL;
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    BYTE pbBuffer[1024] = {0};
    DWORD dwRead = 0;

    do {
        // 打开文件
        hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, 
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (INVALID_HANDLE_VALUE == hFile) {
            break;
        }

        // 获取加密服务提供程序句柄
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, 
                                CRYPT_VERIFYCONTEXT)) {
            break;
        }

        // 创建HASH对象
        if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
            break;
        }

        // 读取文件数据并计算HASH
        while (ReadFile(hFile, pbBuffer, sizeof(pbBuffer), &dwRead, NULL)) {
            if (0 == dwRead) {
                break;
            }
            if (!CryptHashData(hHash, pbBuffer, dwRead, 0)) {
                break;
            }
        }

        // 获取HASH值
        if (!CryptGetHashParam(hHash, HP_HASHVAL, pbHash, pdwHashLen, 0)) {
            break;
        }

        bRet = TRUE;
    } while (FALSE);

    // 清理资源
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    if (hFile) CloseHandle(hFile);

    return bRet;
}

//AES
// AES加密函数
BOOL AESEncrypt(BYTE* pbKey, DWORD dwKeyLen, BYTE* pbData, DWORD* pdwDataLen) 
{
    BOOL bRet = FALSE;
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;

    do {
        // 获取加密服务提供程序句柄
        if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, 
                                PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            break;
        }

        // 创建HASH对象
        if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            break;
        }

        // 导入密钥数据
        if (!CryptHashData(hHash, pbKey, dwKeyLen, 0)) {
            break;
        }

        // 生成AES密钥
        if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
            break;
        }

        // 加密数据
        if (!CryptEncrypt(hKey, 0, TRUE, 0, pbData, pdwDataLen, *pdwDataLen)) {
            break;
        }

        bRet = TRUE;
    } while (FALSE);

    // 清理资源
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);

    return bRet;
}

// AES解密函数
BOOL AESDecrypt(BYTE* pbKey, DWORD dwKeyLen, BYTE* pbData, DWORD* pdwDataLen) 
{
    // 实现类似AESEncrypt，但使用CryptDecrypt替代CryptEncrypt
}

//RSA
// RSA密钥对生成
BOOL GenerateRSAKeyPair(HCRYPTKEY* phPublicKey, HCRYPTKEY* phPrivateKey) 
{
    BOOL bRet = FALSE;
    HCRYPTPROV hProv = NULL;

    do {
        // 获取加密服务提供程序句柄
        if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, 
                                PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            break;
        }

        // 生成密钥对
        if (!CryptGenKey(hProv, AT_KEYEXCHANGE, RSA1024BIT_KEY | CRYPT_EXPORTABLE, 
                        phPrivateKey)) {
            break;
        }

        // 获取公钥
        DWORD dwBlobLen = 0;
        if (!CryptExportKey(*phPrivateKey, 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen)) {
            break;
        }

        BYTE* pbBlob = new BYTE[dwBlobLen];
        if (!CryptExportKey(*phPrivateKey, 0, PUBLICKEYBLOB, 0, pbBlob, &dwBlobLen)) {
            delete[] pbBlob;
            break;
        }

        if (!CryptImportKey(hProv, pbBlob, dwBlobLen, 0, 0, phPublicKey)) {
            delete[] pbBlob;
            break;
        }
        delete[] pbBlob;

        bRet = TRUE;
    } while (FALSE);

    if (!bRet) {
        if (*phPrivateKey) CryptDestroyKey(*phPrivateKey);
        if (*phPublicKey) CryptDestroyKey(*phPublicKey);
    }
    if (hProv) CryptReleaseContext(hProv, 0);

    return bRet;
}

// RSA加密
BOOL RSAEncrypt(HCRYPTKEY hKey, BYTE* pbData, DWORD* pdwDataLen) 
{
    return CryptEncrypt(hKey, 0, TRUE, 0, pbData, pdwDataLen, *pdwDataLen);
}

// RSA解密
BOOL RSADecrypt(HCRYPTKEY hKey, BYTE* pbData, DWORD* pdwDataLen) 
{
    return CryptDecrypt(hKey, 0, TRUE, 0, pbData, pdwDataLen);
}
```
#### Crypto++密码库
```cpp
//HASH
#include <crypto++/sha.h>
#include <crypto++/hex.h>

// 计算SHA256
std::string CalcSHA256(const std::string& data) {
    CryptoPP::SHA256 hash;
    byte digest[CryptoPP::SHA256::DIGESTSIZE];
    
    hash.CalculateDigest(digest, 
        (byte*)data.c_str(), 
        data.length());
        
    CryptoPP::HexEncoder encoder;
    std::string output;
    
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();
    
    return output;
}

//AES
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>

// AES加密
std::string AESEncrypt(const std::string& data, 
                      const byte* key, 
                      const byte* iv) {
    std::string cipher;
    
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);
        
        CryptoPP::StringSource(data, true,
            new CryptoPP::StreamTransformationFilter(enc,
                new CryptoPP::StringSink(cipher)
            )
        );
    }
    catch(const CryptoPP::Exception& e) {
        // 处理异常
    }
    
    return cipher;
}

// AES解密
std::string AESDecrypt(const std::string& cipher,
                      const byte* key,
                      const byte* iv) {
    std::string recovered;
    
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);
        
        CryptoPP::StringSource(cipher, true,
            new CryptoPP::StreamTransformationFilter(dec,
                new CryptoPP::StringSink(recovered)
            )
        );
    }
    catch(const CryptoPP::Exception& e) {
        // 处理异常
    }
    
    return recovered;
}

//RSA
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>

// RSA密钥生成
void GenerateRSAKey(unsigned int keyLength,
                   const char* privFilename,
                   const char* pubFilename) {
    CryptoPP::AutoSeededRandomPool rng;
    
    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, keyLength);
    
    CryptoPP::RSA::PublicKey publicKey(privateKey);
    
    // 保存密钥到文件
    SaveKey(privFilename, privateKey);
    SaveKey(pubFilename, publicKey);
}

// RSA加密
std::string RSAEncrypt(const std::string& message,
                      const CryptoPP::RSA::PublicKey& key) {
    std::string cipher;
    CryptoPP::AutoSeededRandomPool rng;
    
    CryptoPP::RSAES_OAEP_SHA_Encryptor e(key);
    
    CryptoPP::StringSource(message, true,
        new CryptoPP::PK_EncryptorFilter(rng, e,
            new CryptoPP::StringSink(cipher)
        )
    );
    
    return cipher;
}

// RSA解密
std::string RSADecrypt(const std::string& cipher,
                      const CryptoPP::RSA::PrivateKey& key) {
    std::string recovered;
    CryptoPP::AutoSeededRandomPool rng;
    
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(key);
    
    CryptoPP::StringSource(cipher, true,
        new CryptoPP::PK_DecryptorFilter(rng, d,
            new CryptoPP::StringSink(recovered)
        )
    );
    
    return recovered;
}
```
***
# 10、传输技术
#### Socket 通信
##### TCP 通信
函数介绍：包括Socket、bind、htons、inet_addr、listen、accept、send、recv等函数，用于套接字创建、绑定、监听、连接、数据收发等操作。
实现原理：服务器端和客户端都需初始化 Winsock 环境，服务器端创建套接字、绑定、监听、接受连接并收发数据；客户端创建套接字、连接服务器后收发数据。
##### UDP 通信
函数介绍：sendto发送数据到特定目的地，recvfrom接收数据报并获取源地址。
实现原理：初始化 Winsock 环境后，创建套接字、绑定，使用recvfrom和sendto函数收发数据，不区分服务器端和客户端。
#### FTP 通信
##### 基于 Winlnet 的 FTP 文件上传
函数介绍：InternetOpen初始化应用程序，InternetConnect建立互联网连接，FtpOpenFile访问 FTP 服务器文件，InternetWriteFile写入数据。
实现原理：分解 URL 获取信息，初始化库，建立连接，打开文件并上传数据，最后关闭句柄。
##### 基于 Winlnet 的 FTP 文件下载
函数介绍：InternetReadFile从打开的文件中读取数据。
实现原理：与上传类似，分解 URL，初始化库，建立连接，打开文件，获取文件大小后下载数据并关闭句柄。
#### HTTP 通信
##### 基于 Winlnet 的 HTTP 文件上传
函数介绍：HttpOpenRequest创建 HTTP 请求句柄，HttpSendRequestEx发送请求，HttpQueryInfo查询请求信息。
实现原理：分解 URL，建立会话和连接，打开 POST 请求，发送请求并上传数据，获取响应信息头和数据。
##### 基于 Winlnet 的 HTTP 文件下载
实现原理：与上传类似，分解 URL，建立会话和连接，打开 GET 请求，发送请求，获取响应信息头中的数据长度，接收数据。
#### HTTPS 通信
##### 基于 Winlnet 库的 HTTPS 文件上传与下载
与 HTTP 编程操作大体相同，区别在于连接端口（HTTPS 为 443）、请求标志（增加INTERNET FLAG_SECURE等）和安全标志（如SECURITY_FLAG_IGNORE_UNKNOWN_CA）的设置。
***
# 11、功能技术
#### 进程遍历
- CreateToolhelp32Snapshot：获取进程、线程、模块等快照
- Process32First/Process32Next：遍历进程快照
- Thread32First/Thread32Next：遍历线程快照  
- Module32First/Module32Next：遍历进程模块快照
#### 文件遍历
- FindFirstFile：搜索文件或目录
- FindNextFile：继续搜索
- WIN32_FIND_DATA：存储文件信息
#### 桌面截屏
- GetDC：获取设备上下文句柄
- BitBlt：进行位块转换
- ICONINFO：存储图标信息
#### 按键记录
- RegisterRawInputDevices：注册原始输入设备
- GetRawInputData：获取原始输入数据
#### 远程CMD
- CreatePipe：创建匿名管道，获取读写句柄
#### U盘监控
- WM_DEVICECHANGE：消息通知设备更改
- DEV_BROADCAST_HDR和DEV_BROADCAST_VOLUME：存储设备相关信息
#### 文件监控
- ReadDirectoryChangesW：监控文件目录操作
#### 自删除
- MoveFileEx：移动文件
***
# 12、开发环境
***
# 13、文件管理技术
#### 文件管理之内核API
创建文件或目录：ZwCreateFile 函数创建或打开文件和目录，需初始化对象属性，设置相关参数，创建成功后关闭句柄，注意内核下文件路径格式。

删除文件或空目录：ZwDeleteFile 函数删除指定文件或空目录，初始化对象属性后调用该函数，非空目录无法删除。

获取文件大小：ZwQueryInformationFile 函数获取文件信息，包括大小，通过打开文件句柄并调用该函数，从返回结构体中获取文件大小。

读写文件：ZwReadFile 和 ZwWriteFile 函数用于读写文件，需先获取文件句柄，读写操作前设置权限，可申请非分页内存存放数据，注意及时释放。

重命名文件名称：ZwSetInformationFile 函数更改文件信息，实现文件或目录重命名，需初始化对象属性并设置重命名信息。

文件遍历：ZwQueryDirectoryFile 函数遍历文件，获取文件信息并根据偏移值计算下一个文件信息，实现遍历，注意相关参数设置和内存释放。
#### 文件管理之IRP
IoAllocateIrp：申请创建 IRP
IoCallDriver：发送 IRP 给驱动程序

创建或打开文件
向 FSD 发送 IRP_MJ_CREATE 消息的 IRP
包括打开驱动器获取文件对象、申请创建 IRP 并设置、发送 IRP 等待处理等步骤
创建实例回调函数释放 IRP

查询文件信息
创建并构造 IRP_MJ_QUERY_INFORMATION 消息 IRP
设置相关参数后发送给 FSD 并等待处理

设置文件信息
与查询文件信息类似
需对 IRP 结构和 I/O 堆栈空间进行相应设置

读写文件
写入文件需设置 IRP_MJ_WRITE 相关参数
包括缓冲区、偏移量等设置

文件遍历
设置 IRP_MJ_DIRECTORY_CONTROL 相关参数
#### 文件管理之NTFS解析
- 根据分区引导扇区获取相关信息
- 计算根目录文件记录
- 查找属性获取 Data Run
- 定位起始簇和文件名
- 最终找到文件数据
***
# 14、注册表管理技术
#### 注册表管理之内核API
创建注册表键：ZwCreateKey 函数创建或打开注册表项，需指定访问权限、对象属性等参数，可选择创建选项，ZwOpenKey 函数用法类似。

删除注册表键：ZwDeleteKey 函数删除注册表键，需初始化对象属性，指定要删除的键路径。

修改注册表键值：ZwSetValueKey 函数设置注册表键值，可设置不同类型的值，需先打开或创建键，再设置值。

查询注册表键值：ZwQueryValueKey 函数查询注册表键值，获取键值信息，根据指定信息类型返回相应数据。
***
# 15、HOOK技术
#### SSDK HOOK
https://www.cnblogs.com/BoyXiao/archive/2011/09/03/2164574.html
#### 过滤驱动
https://xz.aliyun.com/t/6581?time__1311=n4%2BxnD0Dg7i%3D3D5P7KDsA3xCumGQiTDRiD7q4rID

