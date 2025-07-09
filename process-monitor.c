#include "process-monitor.h"

#define MAX_PROCESSES 1024

int gExit;
PROCESS_CPU_DATA cpuDataArray[MAX_PROCESSES];
int cpuDataCount = 0;

PROCESS_INFO procInfoArray[MAX_PROCESSES];
int procInfoCount = 0;

void SetConsoleColor(int color)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

ULONGLONG FileTimeToULL(const FILETIME *ft)
{
    return (((ULONGLONG)ft->dwHighDateTime) << 32) + ft->dwLowDateTime;
}

void GetSystemTimesWrapper(ULONGLONG* idleTime, ULONGLONG* kernelTime, ULONGLONG* userTime)
{
    FILETIME idle, kernel, user;
    GetSystemTimes(&idle, &kernel, &user);
    *idleTime = FileTimeToULL(&idle);
    *kernelTime = FileTimeToULL(&kernel);
    *userTime = FileTimeToULL(&user);
}

void GetProcessTimesWrapper(HANDLE hProcess, ULONGLONG* kernelTime, ULONGLONG* userTime)
{
    FILETIME creation, exit, kernel, user;
    if(GetProcessTimes(hProcess, &creation, &exit, &kernel, &user))
    {
        *kernelTime = FileTimeToULL(&kernel);
        *userTime = FileTimeToULL(&user);
    }
    else
    {
        *kernelTime = 0;
        *userTime = 0;
    }
}

PROCESS_CPU_DATA* GetCpuDataForPid(DWORD pid)
{
    for(int i=0; i<cpuDataCount; i++)
    {
        if(cpuDataArray[i].pid == pid)
            return &cpuDataArray[i];
    }
    if(cpuDataCount < MAX_PROCESSES)
    {
        cpuDataArray[cpuDataCount].pid = pid;
        cpuDataArray[cpuDataCount].lastKernelTime = 0;
        cpuDataArray[cpuDataCount].lastUserTime = 0;
        cpuDataArray[cpuDataCount].cpuUsage = 0.0;
        cpuDataArray[cpuDataCount].lastRam = 0;
        cpuDataCount++;
        return &cpuDataArray[cpuDataCount - 1];
    }
    return NULL;
}

int compareByRamDesc(const void *a, const void *b)
{
    const PROCESS_INFO *pa = (const PROCESS_INFO*)a;
    const PROCESS_INFO *pb = (const PROCESS_INFO*)b;
    if (pa->ramKb < pb->ramKb) return 1;
    else if (pa->ramKb > pb->ramKb) return -1;
    return 0;
}

void fListProcess(const char *filter, int showCpu)
{
    static ULONGLONG lastSysKernel = 0, lastSysUser = 0;
    ULONGLONG sysIdle, sysKernel, sysUser;

    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if(hProcessSnap == INVALID_HANDLE_VALUE)
    {
        printf("Could not take snapshot\n");
        return;
    }

    if(!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);
        printf("Process information could not be obtained\n");
        return;
    }

    procInfoCount = 0;

    GetSystemTimesWrapper(&sysIdle, &sysKernel, &sysUser);
    ULONGLONG sysKernelDiff = sysKernel - lastSysKernel;
    ULONGLONG sysUserDiff = sysUser - lastSysUser;
    ULONGLONG sysTotalDiff = sysKernelDiff + sysUserDiff;

    do
    {
        if((strlen(filter) == 0) || strstr(pe32.szExeFile, filter))
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            PROCESS_MEMORY_COUNTERS pmc;

            double cpuPercent = 0.0;
            SIZE_T ramKb = 0;
            int ramChanged = 0;

            if(showCpu && hProcess)
            {
                ULONGLONG procKernel, procUser;
                GetProcessTimesWrapper(hProcess, &procKernel, &procUser);

                PROCESS_CPU_DATA *cpuData = GetCpuDataForPid(pe32.th32ProcessID);
                if(cpuData != NULL && lastSysKernel != 0 && lastSysUser != 0)
                {
                    ULONGLONG procKernelDiff = procKernel - cpuData->lastKernelTime;
                    ULONGLONG procUserDiff = procUser - cpuData->lastUserTime;
                    ULONGLONG procTotal = procKernelDiff + procUserDiff;

                    if(sysTotalDiff > 0)
                        cpuPercent = (procTotal * 100.0) / sysTotalDiff;

                    cpuData->cpuUsage = cpuPercent;
                    cpuData->lastKernelTime = procKernel;
                    cpuData->lastUserTime = procUser;
                }
                else if(cpuData != NULL)
                {
                    cpuData->lastKernelTime = procKernel;
                    cpuData->lastUserTime = procUser;
                }
            }

            if(hProcess && GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
            {
                ramKb = pmc.WorkingSetSize / 1024;

                PROCESS_CPU_DATA *cpuData = GetCpuDataForPid(pe32.th32ProcessID);
                if(cpuData != NULL)
                {
                    if(cpuData->lastRam != 0 && cpuData->lastRam != ramKb)
                        ramChanged = 1;
                    cpuData->lastRam = ramKb;
                }
            }

            if(procInfoCount < MAX_PROCESSES)
            {
                procInfoArray[procInfoCount].pid = pe32.th32ProcessID;
                strncpy(procInfoArray[procInfoCount].exeName, pe32.szExeFile, sizeof(procInfoArray[procInfoCount].exeName)-1);
                procInfoArray[procInfoCount].exeName[sizeof(procInfoArray[procInfoCount].exeName)-1] = '\0';
                procInfoArray[procInfoCount].ramKb = ramKb;
                procInfoArray[procInfoCount].cpuUsage = (cpuDataCount > 0) ? GetCpuDataForPid(pe32.th32ProcessID)->cpuUsage : 0.0;
                procInfoArray[procInfoCount].ramChanged = ramChanged;
                procInfoCount++;
            }

            if(hProcess)
                CloseHandle(hProcess);
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    qsort(procInfoArray, procInfoCount, sizeof(PROCESS_INFO), compareByRamDesc);

    if(showCpu)
        printf("%-6s %-30s %10s %10s %s\n", "PID", "Process Name", "RAM (KB)", "CPU (%)", "Change");
    else
        printf("%-6s %-30s %10s\n", "PID", "Process Name", "RAM (KB)");

    printf("-------------------------------------------------------------------------\n");

    for(int i=0; i<procInfoCount; i++)
    {
        if(procInfoArray[i].ramChanged)
            SetConsoleColor(COLOR_HIGHLIGHT);

        if(showCpu)
            printf("%-6u %-30s %10lu %9.2f %s\n",
                procInfoArray[i].pid,
                procInfoArray[i].exeName,
                (unsigned long)procInfoArray[i].ramKb,
                procInfoArray[i].cpuUsage,
                procInfoArray[i].ramChanged ? "*" : "");
        else
            printf("%-6u %-30s %10lu %s\n",
                procInfoArray[i].pid,
                procInfoArray[i].exeName,
                (unsigned long)procInfoArray[i].ramKb,
                procInfoArray[i].ramChanged ? "*" : "");

        if(procInfoArray[i].ramChanged)
            SetConsoleColor(COLOR_DEFAULT);
    }

    lastSysKernel = sysKernel;
    lastSysUser = sysUser;
}

void fKillProcess(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

    if(hProcess == NULL)
    {
        printf("Process could not be terminated (insufficient permissions or incorrect PID): %lu\n", pid);
        return;
    }

    if(TerminateProcess(hProcess, 0))
    {
        printf("PID %lu successfully terminated.\n", pid);
    }
    else
    {
        printf("PID %lu could not be terminated.\n", pid);
    }

    CloseHandle(hProcess);
}

void fListProcessToFile(const char* filter, FILE *fp)
{
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if(hProcessSnap == INVALID_HANDLE_VALUE)
    {
        fprintf(fp, "Could not take snapshot\n");
        return;
    }

    if(!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);
        fprintf(fp, "Process information could not be obtained\n");
        return;
    }

    fprintf(fp, "%-6s %-30s %10s\n", "PID", "Process Name", "RAM (KB)");
    fprintf(fp, "----------------------------------------------------\n");
    do
    {
        if((strlen(filter) == 0) || strstr(pe32.szExeFile, filter))
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            PROCESS_MEMORY_COUNTERS pmc;
            if(hProcess && GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
            {
                fprintf(fp, "%-6u %-30s %10lu\n", pe32.th32ProcessID, pe32.szExeFile, pmc.WorkingSetSize/1024);
            }
            else
            {
                fprintf(fp, "%-6u %-30s %10s\n", pe32.th32ProcessID, pe32.szExeFile, "N/A");
            }

            if(hProcess)
            {
                CloseHandle(hProcess);
            }
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

int main()
{
    int choice;
    DWORD pid;
    char filter[mMaxProcessName] = "";
    FILE *fp;
    int interval = mDefaultInterval;
    int repeat = -1;
    int count = 0;

    while (1)
    {
        printf("\n=== PROCESS MONITOR ===\n");
        printf("1. List Transactions\n");
        printf("2. Kill Process with PID\n");
        printf("3. Search Process\n");
        printf("4. Save process list to file\n");
        printf("5. Instant Monitoring Mode\n");
        printf("6. Exit\n");
        printf("Your choice: ");
        scanf("%d", &choice);

        switch (choice)
        {
            case mListCommand:
                fListProcess("", 0);
                break;

            case mKillCommand:
                printf("PID you want to terminate: ");
                scanf("%lu", &pid);
                fKillProcess(pid);
                break;

            case mSearchCommand:
                printf("Enter the process name filter (or press enter, it will list all): ");
                getchar();
                fgets(filter, sizeof(filter), stdin);
                filter[strcspn(filter, "\n")] = 0;
                fListProcess(filter, 0);
                break;

            case mSaveCommand:
                printf("Process name filter to save (or empty): ");
                getchar();
                fgets(filter, sizeof(filter), stdin);
                filter[strcspn(filter, "\n")] = 0;

                fp = fopen("processlist.txt", "w");
                if(!fp)
                {
                    printf("Could not open file\n");
                }
                else
                {
                    fListProcessToFile(filter, fp);
                    fclose(fp);
                    printf("The process list was saved as 'processlist.txt'.\n");
                }
                break;

            case mWatchCommand:
                printf("How often should it be updated? (default: 2): ");
                scanf("%d", &interval);

                if(interval < mMinInterval)
                    interval = mDefaultInterval;

                printf("How many repetitions? (-1 if unlimited): ");
                scanf("%d", &repeat);

                count = 0;
                cpuDataCount = 0;

                while(repeat < 0 || count < repeat)
                {
                    system("cls");
                    printf("LIVE PROCESS LIST (%d. goruntuleme)\n", count+1);
                    fListProcess("", 1);
                    Sleep(interval * mMiliSecond);
                    count++;
                }
                break;

            case mExitCommand:
                printf("Exiting...\n");
                gExit = 1;
                break;

            default:
                printf("Invalid Selection\n");
                break;
        }

        if(gExit)
        {
            break;
        }
    }
    return 0;
}


