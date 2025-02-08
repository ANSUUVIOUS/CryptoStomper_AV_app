#pragma once

#include <windows.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <iostream>
#include <vector>
#include <string>
#include <strsafe.h>
#include <tchar.h>
#include <stdio.h>

#include <psapi.h>
#include <iostream>
#include <string>

#include "comms.hpp"

#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "psapi.lib")

#define SAMPLE_INTERVAL_MS 1000  // 1 second sample rate
#define HIGH_CPU_THRESHOLD 80  // CPU usage percentage threshold
#define HIGH_GPU_THRESHOLD 70  // GPU usage percentage threshold
#define HIGH_POWER_THRESHOLD 50 // Power in watts (adjust as needed)
#define HIGH_BATTERY_DRAIN -10  // Negative value indicates battery drain
#define CONSISTENT_HIGH_USAGE_DURATION 3  // Number of consecutive readings

#define DEBUG 0


class PerformanceMonitor {
private:
    PDH_HQUERY hQuery;
    PDH_HCOUNTER hCounterCPU, hCounterGPU, hCounterPower, hCounterBattery;
    BOOL hasPowerCounter = TRUE, hasGPUCounter = TRUE, hasBatteryCounter = TRUE;
    typedef struct _SystemMetrics {
        DOUBLE cpuUsage;
        DOUBLE gpuUsage;
        DOUBLE powerUsage;
        DOUBLE batteryDischargeRate;
    } SystemMetrics;

public:
    PerformanceMonitor(VOID) {
        // Initialize PDH Query
        if (PdhOpenQuery(NULL, 0, &hQuery) != ERROR_SUCCESS) {
            std::cerr << "Failed to open PDH Query" << std::endl;
            return;
        }

        // Add CPU counter
        if (PdhAddCounter(hQuery, L"\\Processor Information(_Total)\\% Processor Utility", 0, &hCounterCPU) != ERROR_SUCCESS) {
            std::cerr << "Failed to add CPU counter" << std::endl;
        }
        else {
            std::cout << "Successfully got the CPU Counter" << std::endl;
        }

        //// Add GPU counter (if available)
        ////if (PdhAddCounter(hQuery, L"\\GPU Engine(*)\\Utilization Percentage", 0, &hCounterGPU) != ERROR_SUCCESS) {
        //if (PdhAddCounter(hQuery, L"\\GPU Engine(*engtype_3D)\\Utilization Percentage", 0, &hCounterGPU) != ERROR_SUCCESS) {
        //    std::cerr << "GPU monitoring not available." << std::endl;
        //    hasGPUCounter = false;
        //}
        //else {
        //    std::cout << "Successfully got the GPU Counter" << std::endl;
        //}


        // Add Power Meter counter (if available)
        if (PdhAddCounter(hQuery, L"\\Power Meter(*)\\Power", 0, &hCounterPower) != ERROR_SUCCESS) {
            std::cerr << "Power meter monitoring not available." << std::endl;
            hasPowerCounter = false;
        }
        else {
            std::cout << "Successfully got the Power Meter" << std::endl;
        }


        // Add Battery Discharge Rate counter (if available)
        if (PdhAddCounter(hQuery, L"\\Battery Status(*)\\Discharge Rate", 0, &hCounterBattery) != ERROR_SUCCESS) {
            std::cerr << "Battery discharge monitoring not available." << std::endl;
            hasBatteryCounter = false;
        }
        else {
            std::cout << "Successfully got the Battery Discharge rate" << std::endl;
        }


        // Initial data collection
        PdhCollectQueryData(hQuery);
    }

    ~PerformanceMonitor(VOID) {
        PdhCloseQuery(hQuery);
    }

    std::string RunPowerShellCommand(const std::wstring& command) {
        HANDLE hReadPipe, hWritePipe;
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

        // Create Pipe for capturing PowerShell output
        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            std::cerr << "❌ Failed to create pipe.\n";
            return "";
        }

        // PowerShell execution command
        std::wstring psCommand = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"" + command + L"\"";

        // Set up the process startup info
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        SecureZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.hStdOutput = hWritePipe;
        si.hStdError = hWritePipe;
        si.dwFlags |= STARTF_USESTDHANDLES;

        SecureZeroMemory(&pi, sizeof(pi));

        // Start PowerShell process
        if (!CreateProcessW(NULL, &psCommand[0], NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            std::cerr << "❌ Failed to start PowerShell.\n";
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return "";
        }

        // Close the write pipe handle as it's no longer needed
        CloseHandle(hWritePipe);

        // Read PowerShell output
        std::string output;
        char buffer[4096];
        DWORD bytesRead;
        while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            output += buffer;
        }

        // Cleanup
        CloseHandle(hReadPipe);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return output;
    }

    BOOL GetTextSectionInfo(PVOID pBaseAddress, PVOID* pTextSectionAddress, SIZE_T* pTextSectionSize) {
        // Check if the base address is valid
        if (!pBaseAddress) {
            printf("Invalid base address\n");
            return FALSE;
        }

        // Get the DOS header
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            printf("Invalid DOS header\n");
            return FALSE;
        }

        // Get the NT headers
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pBaseAddress + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            printf("Invalid PE header\n");
            return FALSE;
        }

        // Get the section table
        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

        // Iterate through the section table to find the .text section
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            if (strcmp((PCHAR)pSectionHeader[i].Name, ".text") == 0) {
                // Found the .text section
                *pTextSectionAddress = (PBYTE)pBaseAddress + pSectionHeader[i].VirtualAddress;
                *pTextSectionSize = pSectionHeader[i].Misc.VirtualSize;
                return TRUE;
            }
        }

        // .text section not found
        printf(".text section not found\n");
        return FALSE;
    }


    DOUBLE getCPUUsage(VOID) {
        PDH_FMT_COUNTERVALUE counterValue = { 0 };
        PDH_STATUS status = 0;
        PDH_STATUS init = PdhCollectQueryData(hQuery);

        if (init == ERROR_SUCCESS &&
            (status = PdhGetFormattedCounterValue(hCounterCPU, PDH_FMT_DOUBLE, NULL, &counterValue)) == ERROR_SUCCESS) {
            return counterValue.doubleValue;
        }
        else {
            if (DEBUG)
            {
                std::cerr << "Couldn't get the the CPU Usage: " + std::to_string(status) + " " + std::to_string(init) << std::endl;
            }
        }

        return -ERROR_INTERNAL_ERROR; // Indicate failure
    }

    VOID GetCpuUsageForProcess(DWORD pid, CONST CHAR* processName) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            fprintf(stderr, "Failed to open process %s (PID: %lu).\n", processName, pid);
            return;
        }

        ULONGLONG lastCycles, currentCycles;
        if (!QueryProcessCycleTime(hProcess, &lastCycles)) {
            fprintf(stderr, "Failed to query process cycles for %s (PID: %lu).\n", processName, pid);
            CloseHandle(hProcess);
            return;
        }

        // Sleep for a very short duration (e.g., 10ms instead of 1s)
        Sleep(10);

        if (!QueryProcessCycleTime(hProcess, &currentCycles)) {
            fprintf(stderr, "Failed to query process cycles for %s (PID: %lu).\n", processName, pid);
            CloseHandle(hProcess);
            return;
        }

        ULONGLONG cycleDiff = currentCycles - lastCycles;

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        DWORD numProcessors = sysInfo.dwNumberOfProcessors;

        printf("Process %s CPU Usage: %.2f%%\n", processName, (cycleDiff / 10000.0) / numProcessors);

        CloseHandle(hProcess);
    }

    //VOID GetCpuUsageForProcess(DWORD pid, CONST CHAR* processName) {
    //    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    //    if (!hProcess) {
    //        fprintf(stderr, "Failed to open process %s (PID: %lu).\n", processName, pid);
    //        return;
    //    }

    //    FILETIME ftCreation, ftExit, ftKernel, ftUser;
    //    ULARGE_INTEGER lastKernel, lastUser, currentKernel, currentUser;

    //    // Initial time capture
    //    if (!GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
    //        fprintf(stderr, "Failed to get process times for %s (PID: %lu).\n", processName, pid);
    //        CloseHandle(hProcess);
    //        return;
    //    }

    //    lastKernel.LowPart = ftKernel.dwLowDateTime;
    //    lastKernel.HighPart = ftKernel.dwHighDateTime;
    //    lastUser.LowPart = ftUser.dwLowDateTime;
    //    lastUser.HighPart = ftUser.dwHighDateTime;

    //    //Sleep(1000); // Wait for 1 second to measure CPU usage

    //    // Capture process times again
    //    if (!GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
    //        fprintf(stderr, "Failed to get process times for %s (PID: %lu).\n", processName, pid);
    //        CloseHandle(hProcess);
    //        return;
    //    }

    //    currentKernel.LowPart = ftKernel.dwLowDateTime;
    //    currentKernel.HighPart = ftKernel.dwHighDateTime;
    //    currentUser.LowPart = ftUser.dwLowDateTime;
    //    currentUser.HighPart = ftUser.dwHighDateTime;

    //    // Calculate CPU usage as a percentage
    //    ULONGLONG kernelDiff = currentKernel.QuadPart - lastKernel.QuadPart;
    //    ULONGLONG userDiff = currentUser.QuadPart - lastUser.QuadPart;
    //    ULONGLONG totalDiff = kernelDiff + userDiff;

    //    SYSTEM_INFO sysInfo;
    //    GetSystemInfo(&sysInfo);
    //    DWORD numProcessors = sysInfo.dwNumberOfProcessors;

    //    printf("Process %s CPU Usage: %.2f%%\n", processName, (totalDiff / 10000.0) / numProcessors);

    //    CloseHandle(hProcess);
    //}



    std::string GetProcessName(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            return "<Unknown>";  // Return default if process cannot be opened
        }

        //TCHAR processName[MAX_PATH] = TEXT("<Unknown>");
        CHAR processName[MAX_PATH] = "<Unknown>";

        // Get process name
        if (GetModuleBaseNameA(hProcess, NULL, processName, sizeof(processName) / sizeof(CHAR)) == 0) {
            CloseHandle(hProcess);
            return "<Unknown>";
        }

        CloseHandle(hProcess);
        return std::string(processName);  // Return as std::string
    }

    DOUBLE getGPUUsage(VOID) {
        //if (!hasGPUCounter) {
        //    return -1;
        //}
        //PDH_FMT_COUNTERVALUE counterValue = { 0 };
        //PDH_STATUS status = 0;
        //PDH_STATUS init = PdhCollectQueryData(hQuery);

        //(LONG)PDH_INVALID_ARGUMENT;

        //if (PdhCollectQueryData(hQuery) == ERROR_SUCCESS &&
        //    (status = PdhGetFormattedCounterValue(hCounterGPU, PDH_FMT_DOUBLE, NULL, &counterValue)) == ERROR_SUCCESS) {
        //    return counterValue.doubleValue;
        //}
        //else {
        //    if (DEBUG)
        //    {
        //        std::cerr << "Couldn't get the the GPU Usage: " + std::to_string(status) + " " + std::to_string(init) << std::endl;
        //    }

        //}

        //return -ERROR_INTERNAL_ERROR;
    // PowerShell command to get total GPU usage


        std::wstring psCommand = LR"(
        $GpuUseTotal = (((Get-Counter \"\GPU Engine(*engtype_3D)\Utilization Percentage\").CounterSamples | where CookedValue).CookedValue | measure -sum).sum;
        Write-Output "$([math]::Round($GpuUseTotal,2))%"
    )";

        std::string gpuUsage = RunPowerShellCommand(psCommand);

        // Remove any trailing whitespace, newlines, or percentage symbols
        gpuUsage.erase(std::remove_if(gpuUsage.begin(), gpuUsage.end(), [](unsigned char c) {
            return std::isspace(c) || c == '%';
            }), gpuUsage.end());

        // Convert to double
        double gpuUsageValue = 0.0;
        try {
            gpuUsageValue = std::stod(gpuUsage);
        }
        catch (const std::exception& e) {
            std::cerr << "❌ Error converting GPU usage to double: " << e.what() << std::endl;
            return  -ERROR_INTERNAL_ERROR;
        }

        return gpuUsageValue;
        
    }

    DOUBLE getPowerUsage(VOID) {
        if (!hasPowerCounter) {
            return -1;
        }
        PDH_FMT_COUNTERVALUE counterValue = { 0 };
        PDH_STATUS status = 0;
        PDH_STATUS init = PdhCollectQueryData(hQuery);
        if (PdhCollectQueryData(hQuery) == ERROR_SUCCESS &&
            (status = PdhGetFormattedCounterValue(hCounterPower, PDH_FMT_DOUBLE, NULL, &counterValue)) == ERROR_SUCCESS) {
            return counterValue.doubleValue;
        }
        else {
            if (DEBUG)
            {
                std::cerr << "Couldn't get the the Power Usage: " + std::to_string(status) + " " + std::to_string(init) << std::endl;
            }
        }

        return -ERROR_INTERNAL_ERROR;
    }

    DOUBLE getBatteryDischargeRate(VOID) {
        if (!hasBatteryCounter) {
            return -1;
        }
        PDH_STATUS status = 0;
        PDH_FMT_COUNTERVALUE counterValue = { 0 };
        PDH_STATUS init = PdhCollectQueryData(hQuery);

        if (init == ERROR_SUCCESS &&
            (status = PdhGetFormattedCounterValue(hCounterBattery, PDH_FMT_DOUBLE, NULL, &counterValue)) == ERROR_SUCCESS) {
            return counterValue.doubleValue;
        }
        else {
            if (DEBUG)
            {
                std::cerr << "Couldn't get the the Battery Usage: " + std::to_string(status) + " " + std::to_string(init) << std::endl;
            }
        }

        return -ERROR_INTERNAL_ERROR;
    }

    SystemMetrics collectMetrics() {
        return { getCPUUsage(), getGPUUsage(), getPowerUsage(), getBatteryDischargeRate() };
    }

    // Function to determine if power usage is consistently high
    BOOL isConsistentlyHighUsage() {
        INT highUsageCount = 0;

        while (TRUE) {
            Sleep(SAMPLE_INTERVAL_MS);
            SystemMetrics metrics = collectMetrics();
            std::cout << std::endl;

            if (metrics.cpuUsage >= 0)
            {
                std::cout << "CPU Usage: " << metrics.cpuUsage << "%" << std::endl;
            }

            if (metrics.gpuUsage >= 0)
            {
                std::cout << "GPU Usage: " << metrics.gpuUsage << "%" << std::endl;
            }

            if (metrics.powerUsage >= 0)
            {
                std::cout << "Power Usage: " << metrics.powerUsage << " watts" << std::endl;
            }

            if (metrics.batteryDischargeRate >= 0)
            {
                std::cout << "Battery Discharge Rate: " << metrics.batteryDischargeRate << " mW" << std::endl;
            }

            bool isHighUsage = false;

            if (metrics.cpuUsage > HIGH_CPU_THRESHOLD) {
                std::cout << "[ALERT] High CPU usage detected!" << std::endl;
                isHighUsage = true;
            }
            if (metrics.gpuUsage > HIGH_GPU_THRESHOLD) {
                std::cout << "[ALERT] High GPU usage detected!" << std::endl;
                isHighUsage = true;
            }
            if (metrics.powerUsage > HIGH_POWER_THRESHOLD) {
                std::cout << "[ALERT] High Power usage detected!" << std::endl;
                isHighUsage = true;
            }
            if (metrics.batteryDischargeRate < HIGH_BATTERY_DRAIN) {
                std::cout << "[ALERT] High battery discharge detected!" << std::endl;
                isHighUsage = true;
            }


            // If any metric is above threshold, increase count
            if (isHighUsage) {
                highUsageCount++;
            }
            else {
                highUsageCount = 0;
            }

            // If high usage continues for a set duration, return true
            if (highUsageCount >= CONSISTENT_HIGH_USAGE_DURATION) {
                std::cout << "[CRITICAL] System has had consistently high power usage for "
                    << CONSISTENT_HIGH_USAGE_DURATION << " seconds!" << std::endl;
                return TRUE;
            }
        }
        return FALSE;
    }
};



// Function to execute PowerShell command and return output as a string
std::string RunPowerShellCommand(const std::wstring& command) {
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    // Create Pipe for capturing PowerShell output
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        std::cerr << "❌ Failed to create pipe.\n";
        return "";
    }

    // PowerShell execution command
    std::wstring psCommand = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"" + command + L"\"";

    std::wcout << psCommand << std::endl;

    // Set up the process startup info
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES;

    ZeroMemory(&pi, sizeof(pi));

    // Start PowerShell process
    if (!CreateProcessW(NULL, &psCommand[0], NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        std::cerr << "❌ Failed to start PowerShell.\n";
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return "";
    }

    // Close the write pipe handle as it's no longer needed
    CloseHandle(hWritePipe);

    // Read PowerShell output
    std::string output;
    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }

    // Cleanup
    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return output;
}

DOUBLE GetGpuUsageForProcess(DWORD pid, CONST CHAR* processName) {
    PDH_HQUERY query;
    PDH_HCOUNTER gpuCounter;
    PDH_FMT_COUNTERVALUE counterValue;
    PDH_STATUS status;

    // Format GPU usage counter path dynamically for the given PID
    TCHAR counterPath[256];
    _stprintf_s(counterPath, TEXT("\\GPU Engine(pid_$(%u)*engtype_3D)\\Utilization Percentage"), pid);

    // Open a PDH query
    if (PdhOpenQuery(NULL, 0, &query) != ERROR_SUCCESS) {
        std::cerr << "❌ Failed to open PDH query.\n";
        return -1.0;
    }

    // Add GPU Engine Utilization counter for the specific process
    status = PdhAddCounter(query, counterPath, 0, &gpuCounter);
    if (status != ERROR_SUCCESS) {
        std::cerr << "❌ Failed to add GPU counter. Error: 0x" << std::hex << status << "\n";
        PdhCloseQuery(query);
        return -1.0;
    }

    // Allow PDH counters some time to collect valid data
    //Sleep(1000);

    // Collect query data
    status = PdhCollectQueryData(query);
    if (status != ERROR_SUCCESS) {
        std::cerr << "❌ Failed to collect PDH query data. Error: 0x" << std::hex << status << "\n";
        PdhCloseQuery(query);
        return -1.0;
    }

    // Retrieve formatted counter value
    status = PdhGetFormattedCounterValue(gpuCounter, PDH_FMT_DOUBLE, NULL, &counterValue);
    if (status == ERROR_SUCCESS) {
        std::cout << "🎮 GPU Usage for PID " << pid << ": " << counterValue.doubleValue << "%\n";
    }
    else {
        std::cerr << "❌ Failed to retrieve GPU usage counter value. Error: 0x" << std::hex << status << "\n";
    }

    // Cleanup
    PdhCloseQuery(query);

    return counterValue.doubleValue;
}

//VOID GetGpuUsageForProcess(DWORD pid, CONST CHAR * processName) {
//    PDH_HQUERY query;
//    PDH_HCOUNTER gpuCounter;
//    PDH_FMT_COUNTERVALUE counterValue;
//    TCHAR counterPath[256];
//    PDH_STATUS status;
//
//    // Open a PDH query
//    if (PdhOpenQuery(NULL, 0, &query) != ERROR_SUCCESS) {
//        fprintf(stderr, "Failed to open PDH query.\n");
//        return;
//    }
//
//    // Use StringCchPrintf instead of deprecated swprintf/_stprintf
//    HRESULT hr = StringCchPrintf(counterPath, ARRAYSIZE(counterPath), TEXT("\\GPU Engine(pid_%u*engtype_3D)\\Utilization Percentage"), pid);
//    if (FAILED(hr)) {
//        fprintf(stderr, "Failed to format counter path.\n");
//        PdhCloseQuery(query);
//        return;
//    }
//
//    // Add GPU Engine Utilization counter for the process
//    status = PdhAddCounter(query, counterPath, 0, &gpuCounter);
//    if (status != ERROR_SUCCESS) {
//        fprintf(stderr, "Failed to add GPU engine counter. Error: 0x%x\n", status);
//        PdhCloseQuery(query);
//        return;
//    }
//
//    // Collect query data
//    if (PdhCollectQueryData(query) != ERROR_SUCCESS) {
//        fprintf(stderr, "Failed to collect query data.- %d\n", GetLastError());
//        PdhCloseQuery(query);
//        return;
//    }
//
//    // Get GPU usage
//    if (PdhGetFormattedCounterValue(gpuCounter, PDH_FMT_DOUBLE, NULL, &counterValue) == ERROR_SUCCESS) {
//        printf("Process %s GPU Engine Usage: %.2f%%\n", processName, counterValue.doubleValue);
//    }
//    else {
//        fprintf(stderr, "Failed to get GPU usage counter value.\n");
//    }
//
//    // Close the PDH query
//    PdhCloseQuery(query);
//}


INT systemtest() {

    PerformanceMonitor monitor;
    CCommunication comms;

    BOOL results = comms.Initialize();
    if (!results) {
        printf("Issue starting driver. Please ensure driver is correctly installed.");
        return ERROR_INVALID_HANDLE;
    }

    if (TRUE){
    //if (monitor.isConsistentlyHighUsage()) {
        results = comms.GetProcesses();
        if (!results || sizeof(comms.ProcessList) == 0) {
            printf("Issue getting processes associated to the system. Therefore exiting.");
            return ERROR_ACCESS_DENIED;
        }

        for (DWORD idx = 0; idx < comms.ProcessList->size; idx++) {
            DWORD pid = (DWORD)comms.ProcessList->processes[idx].ProcessID;
            if (pid > 0) {
                std::string processName = monitor.GetProcessName(pid);
                //printf("%Process name: %s\n", processName.c_str());
                monitor.GetCpuUsageForProcess(pid, processName.c_str());
            }
        }

    }

    return ERROR_SUCCESS;
}

// Function to read bytes from the .text section of another process
BYTE* ReadTextSectionBytes(HANDLE hProcess, PVOID pTextSectionAddress, SIZE_T textSectionSize) {
    // Allocate a buffer to hold the .text section bytes
    PBYTE pBuffer = (PBYTE)calloc(textSectionSize, sizeof(BYTE));
    if (!pBuffer) {
        printf("Failed to allocate memory for .text section buffer\n");
        return NULL;
    }

    // Read the .text section bytes from the target process
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, pTextSectionAddress, pBuffer, textSectionSize, &bytesRead)) {
        printf("Failed to read .text section bytes. Error: %d\n", GetLastError());
        free(pBuffer);
        return NULL;
    }

    // Ensure all bytes were read
    if (bytesRead != textSectionSize) {
        printf("Warning: Only read %zu out of %zu bytes\n", bytesRead, textSectionSize);
    }

    return pBuffer;
}

// Function to read memory from another process
BOOL ReadProcessMemorySafe(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) {
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &bytesRead) || bytesRead != nSize) {
        printf("Failed to read memory at address 0x%p. Error: %d\n", lpBaseAddress, GetLastError());
        return FALSE;
    }
    return TRUE;
}

// Function to get the .text section address and size of another process
BOOL GetProcessTextSectionInfo(DWORD pid, PVOID pBaseAddress, PVOID* pTextSectionAddress, SIZE_T* pTextSectionSize, PBYTE* pTextMem) {
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        printf("Failed to open process (PID: %d). Error: %d\n", pid, GetLastError());
        return FALSE;
    }

    // Read the DOS header
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemorySafe(hProcess, pBaseAddress, &dosHeader, sizeof(dosHeader))) {
        CloseHandle(hProcess);
        return FALSE;
    }

    // Validate the DOS header
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS header\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    // Read the NT headers
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemorySafe(hProcess, (PBYTE)pBaseAddress + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders))) {
        CloseHandle(hProcess);
        return FALSE;
    }

    // Validate the NT headers
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT headers\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    // Read the section headers
    IMAGE_SECTION_HEADER sectionHeader;
    DWORD sectionOffset = dosHeader.e_lfanew + sizeof(ntHeaders.Signature) + sizeof(ntHeaders.FileHeader) + ntHeaders.FileHeader.SizeOfOptionalHeader;

    // Iterate through the section table to find the .text section
    for (DWORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        if (!ReadProcessMemorySafe(hProcess, (PBYTE)pBaseAddress + sectionOffset + (i * sizeof(sectionHeader)), &sectionHeader, sizeof(sectionHeader))) {
            CloseHandle(hProcess);
            return FALSE;
        }

        // Check if this is the .text section
        if (strcmp((char*)sectionHeader.Name, ".text") == 0) {
            // Calculate the .text section address and size
            *pTextSectionAddress = (PBYTE)pBaseAddress + sectionHeader.VirtualAddress;
            *pTextSectionSize = sectionHeader.Misc.VirtualSize;
            *pTextMem = ReadTextSectionBytes(hProcess, *pTextSectionAddress, *pTextSectionSize);
            CloseHandle(hProcess);
            return TRUE;
        }
    }

    // .text section not found
    printf(".text section not found for process %d\n", pid);
    CloseHandle(hProcess);
    return FALSE;
}

// Main function
INT main(INT argc, LPSTR * argv) {

    CCommunication comms;
    PerformanceMonitor monitor;

    if (argc < 2) {
        printf("Too little arguments - therefore exiting.\n");
        return -1;
    }

    BOOL results = comms.Initialize();
    if (!results) {
        return -1;
    }

    SIZE_T edge_text_size = 0;
    PVOID edge_text_address = NULL;

    PVOID edge_address = comms.GetImageBase(std::stoi(argv[1]))->ImageBase;
    PBYTE edge_text_memory = NULL;

    GetProcessTextSectionInfo(std::stoi(argv[1]), edge_address, &edge_text_address, &edge_text_size, &edge_text_memory);
    free(edge_text_memory);

    comms.KillProcess(std::stoi(argv[1]));

    printf("%d is the text size\n", edge_text_size);



   //return systemtest();
}




