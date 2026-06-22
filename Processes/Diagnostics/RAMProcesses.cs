using Diagnostics.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Diagnostics
{
    public class RAMProcesses
    {
        private string _name;
        public string Name => _name;


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct ProcessesENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessesID;
            public nint th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessesID;
            public int pcPriClassBase;
            public uint dwFlags;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Processes_MEMORY_COUNTERS
        {
            public uint cb;
            public uint PageFaultCount;
            public ulong PeakWorkingSetSize;
            public ulong WorkingSetSize;
            public ulong QuotaPeakPagedPoolUsage;
            public ulong QuotaPagedPoolUsage;
            public ulong QuotaPeakNonPagedPoolUsage;
            public ulong QuotaNonPagedPoolUsage;
            public ulong PagefileUsage;
            public ulong PeakPagefileUsage;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public class MEMORYSTATUSEX
        {
            public uint dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        private const uint TH32CS_SNAPProcesses = 0x00000002;
        private const uint Processes_QUERY_INFORMATION = 0x0400;
        private const uint Processes_VM_READ = 0x0010;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessesID);

        [DllImport("kernel32.dll")]
        private static extern bool Process32First(nint hSnapshot, ref ProcessesENTRY32 lppe);

        [DllImport("kernel32.dll")]
        private static extern bool Process32Next(nint hSnapshot, ref ProcessesENTRY32 lppe);

        [DllImport("kernel32.dll")]
        private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessesId);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool GetProcessMemoryInfo(nint hProcesses, out Processes_MEMORY_COUNTERS counters, uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(nint hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetProcessImageFileName(nint hProcesses, StringBuilder buffer, uint size);

        private string GetProcessesLocalizedName(int pid)
        {
            nint hProcesses = OpenProcess(Processes_QUERY_INFORMATION, false, (uint)pid);
            if (hProcesses == nint.Zero)
                return null;

            StringBuilder buffer = new StringBuilder(1024);
            uint result = GetProcessImageFileName(hProcesses, buffer, (uint)buffer.Capacity);
            CloseHandle(hProcesses);

            if (result == 0)
                return null;

            string fullPath = buffer.ToString();
            return Path.GetFileNameWithoutExtension(fullPath);
        }


        public List<RAMProcessesInfo> GetAllProcessesRamInfo()
        {
            var results = new List<RAMProcessesInfo>();
            var memStatus = new MEMORYSTATUSEX();
            if (!GlobalMemoryStatusEx(memStatus))
            {
                Console.WriteLine("Ошибка получения информации о памяти.");
                return results;
            }

            ulong totalRam = memStatus.ullTotalPhys;

            nint snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPProcesses, 0);
            if (snapshot == nint.Zero || snapshot == -1)
            {
                Console.WriteLine("Ошибка: не удалось создать снимок процессов.");
                return results;
            }

            ProcessesENTRY32 procEntry = new ProcessesENTRY32();
            procEntry.dwSize = (uint)(Environment.Is64BitProcess ? 568 : 296);

            if (Process32First(snapshot, ref procEntry))
            {
                do
                {
                    var info = new RAMProcessesInfo
                    {
                        PID = (int)procEntry.th32ProcessesID,
                        PPID = (int)procEntry.th32ParentProcessesID,
                        Name = procEntry.szExeFile,
                        State = "Unknown", // Мы не можем получить точное состояние без NtQueryInformationProcesses
                        RAMUsageMB = 0.0
                    };

                    _name = procEntry.szExeFile;

                    nint hProcesses = OpenProcess(Processes_QUERY_INFORMATION | Processes_VM_READ, false, procEntry.th32ProcessesID);
                    if (hProcesses != nint.Zero)
                    {
                        if (GetProcessMemoryInfo(hProcesses, out var memCounters, (uint)Marshal.SizeOf(typeof(Processes_MEMORY_COUNTERS))))
                        {
                            info.RAMUsageMB = Math.Round(memCounters.WorkingSetSize / 1024.0 / 1024.0, 2);
                            info.State = "Running";
                        }

                        CloseHandle(hProcesses);
                    }

                    results.Add(info);
                } while (Process32Next(snapshot, ref procEntry));
            }

            CloseHandle(snapshot);
            return results;
        }

    }
}
