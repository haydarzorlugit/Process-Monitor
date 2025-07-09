#ifndef PROCESS_MONITOR_H
#define PROCESS_MONITOR_H

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>


#define  mListCommand        1
#define  mKillCommand        2
#define  mSearchCommand      3
#define  mSaveCommand        4
#define  mWatchCommand       5
#define  mExitCommand        6


#define  mMaxProcessName     20
#define  mMinInterval        1
#define  mDefaultInterval    2
#define  mMiliSecond         1000


#define COLOR_DEFAULT 7
#define COLOR_HIGHLIGHT 14 // Sarı



typedef struct _PROCESS_CPU_DATA {
    DWORD pid;
    ULONGLONG lastKernelTime;
    ULONGLONG lastUserTime;
    double cpuUsage;
    SIZE_T lastRam;
} PROCESS_CPU_DATA;

typedef struct _PROCESS_INFO {
    DWORD pid;
    char exeName[260];
    SIZE_T ramKb;
    double cpuUsage;
    int ramChanged;
} PROCESS_INFO;


void SetConsoleColor(int color);
ULONGLONG FileTimeToULL(const FILETIME *ft);
void GetSystemTimesWrapper(ULONGLONG* idleTime, ULONGLONG* kernelTime, ULONGLONG* userTime);
void GetProcessTimesWrapper(HANDLE hProcess, ULONGLONG* kernelTime, ULONGLONG* userTime);
PROCESS_CPU_DATA* GetCpuDataForPid(DWORD pid);

void fListProcess(const char *filter, int showCpu);
void fKillProcess(DWORD pid);
void fListProcessToFile(const char* filter, FILE *fp);

#endif // PROCESS_MONITOR_H
