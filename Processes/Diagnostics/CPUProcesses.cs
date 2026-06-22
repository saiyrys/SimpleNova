using Diagnostics.Models;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Diagnostics
{
    public class CPUProcesses
    {
        private int _ppid;
        public int PPID => _ppid;

        private string _name;
        public string Name => _name;

        private double totalPercentUsage;
        public double TotalPercentUsage => totalPercentUsage;

        private CancellationTokenSource _cts = new CancellationTokenSource();


        List<CPUProcessesInfo> _ProcessesInfo = new List<CPUProcessesInfo>();

        private Dictionary<int, (ulong KernelTime, ulong UserTime)> _lastSnapshot = new();

        public List<CPUProcessesInfo> GetProcessesList()
        {
            _ProcessesInfo.Clear();
            GetProcesses();
            return _ProcessesInfo;
        }

        public double GetLastCpuUsage()
        {
            return Math.Round(totalPercentUsage, 2);
        }


        public void StopCpuMonitoring()
        {
            _cts.Cancel();
        }

        public void GetProcesses()
        {
            uint bufferSize = 0x10000;

            nint buffer = Marshal.AllocHGlobal((int)bufferSize);

            try
            {
                int status = NtQuerySystemInformation(
                    5,
                    buffer,
                    bufferSize,
                    out uint returnLength);

                if(status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buffer);
                    bufferSize = returnLength;
                    buffer = Marshal.AllocHGlobal((int)bufferSize);

                    status = NtQuerySystemInformation(
                        5,
                        buffer,
                        bufferSize,
                        out returnLength
                        );
                }

                if (status != 0)
                {
                    Console.WriteLine("Ошибка запроса NtQuerySystemInformation: " + status);
                    return;
                }

                nint current = buffer;

                var newSnapshot = new Dictionary<int, (ulong KernelTime, ulong UserTime)>();
                var newProcessesInfo = new List<CPUProcessesInfo>();
                int ProcessesorCount = Environment.ProcessorCount;
                var now = DateTime.UtcNow;
                TimeSpan deltaTime = TimeSpan.FromMilliseconds(500);

                while (true)
                {
                    SYSTEM_Processes_INFORMATION spi = Marshal.PtrToStructure<SYSTEM_Processes_INFORMATION>(current);

                    // Получаем имя процесса
                    string ProcessesName = "<unnamed>";
                    if (spi.ImageName.Buffer != nint.Zero)
                    {
                        ProcessesName = Marshal.PtrToStringUni(spi.ImageName.Buffer, spi.ImageName.Length / 2);
                    }

                    int pid = spi.ProcessesId.ToInt32();

                    // Получаем время работы процесса
                    ulong kernelTime = spi.KernelTime;
                    ulong userTime = spi.UserTime;

                    // Рассчитываем CPU нагрузку
                    double cpuUsage = 0;
                    if (_lastSnapshot.TryGetValue(pid, out var lastTimes))
                    {
                        ulong totalTime = kernelTime + userTime - (lastTimes.KernelTime + lastTimes.UserTime);
                        ulong totalDelta = (ulong)(deltaTime.TotalMilliseconds * 10000);
                        cpuUsage = (double)totalTime / totalDelta * ProcessesorCount * 100;
                    }

                    newProcessesInfo.Add(new CPUProcessesInfo
                    {
                        PID = pid,
                        PPID = spi.InheritedFromProcessesId.ToInt32(),
                        Name = ProcessesName,
                        CpuUsagePercent = cpuUsage
                    });

                    // Сохраняем текущие значения времени
                    newSnapshot[pid] = (kernelTime, userTime);
                    totalPercentUsage += cpuUsage;

                    if (spi.NextEntryOffset == 0)
                        break;
                    
                    /*Console.WriteLine($"PID: {spi.ProcessesId}  | PPID: {spi.InheritedFromProcessesId} | Имя процесса: {ProcessesName}");*/

                    current = nint.Add(current, (int)spi.NextEntryOffset);
                }

                _lastSnapshot = newSnapshot;
                _ProcessesInfo = newProcessesInfo;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public void StartCpuMonitoring(int intervalMs = 500)
        {
            Task.Run(async () =>
            {
                int coreCount = Environment.ProcessorCount;
                int size = Marshal.SizeOf<SYSTEM_ProcessesOR_PERFORMANCE_INFORMATION>();
                nint buffer = Marshal.AllocHGlobal(size * coreCount);

                try
                {
                    while (!_cts.Token.IsCancellationRequested)
                    {
                        NtQuerySystemInformation(0x8, buffer, (uint)(size * coreCount), out _);
                        var data1 = new SYSTEM_ProcessesOR_PERFORMANCE_INFORMATION[coreCount];
                        for (int i = 0; i < coreCount; i++)
                            data1[i] = Marshal.PtrToStructure<SYSTEM_ProcessesOR_PERFORMANCE_INFORMATION>(nint.Add(buffer, i * size));

                        await Task.Delay(intervalMs, _cts.Token);

                        NtQuerySystemInformation(0x8, buffer, (uint)(size * coreCount), out _);
                        var data2 = new SYSTEM_ProcessesOR_PERFORMANCE_INFORMATION[coreCount];
                        for (int i = 0; i < coreCount; i++)
                            data2[i] = Marshal.PtrToStructure<SYSTEM_ProcessesOR_PERFORMANCE_INFORMATION>(nint.Add(buffer, i * size));

                        long totalIdle = 0;
                        long totalKernel = 0;
                        long totalUser = 0;

                        for (int i = 0; i < coreCount; i++)
                        {
                            totalIdle += data2[i].IdleTime - data1[i].IdleTime;
                            totalKernel += data2[i].KernelTime - data1[i].KernelTime;
                            totalUser += data2[i].UserTime - data1[i].UserTime;
                        }

                        long totalSystem = totalKernel + totalUser;

                        totalPercentUsage = totalSystem == 0 ? 0 : (1.0 - (double)totalIdle / totalSystem) * 100;
                    }
                }
                catch (TaskCanceledException) { }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            });
        }

        public double GetTotalCpuUsage(int delayMs = 300)
        {
            int coreCount = Environment.ProcessorCount;
            int size = Marshal.SizeOf<SYSTEM_ProcessesOR_PERFORMANCE_INFORMATION>();
            nint buffer = Marshal.AllocHGlobal(size * coreCount);

            try
            {
                // Первый снимок
                NtQuerySystemInformation(0x8, buffer, (uint)(size * coreCount), out _);
                var data1 = new SYSTEM_ProcessesOR_PERFORMANCE_INFORMATION[coreCount];
                for (int i = 0; i < coreCount; i++)
                {
                    nint ptr = nint.Add(buffer, i * size);
                    data1[i] = Marshal.PtrToStructure<SYSTEM_ProcessesOR_PERFORMANCE_INFORMATION>(ptr);
                }

                Thread.Sleep(delayMs); // Измеряем за 300 мс

                // Второй снимок
                NtQuerySystemInformation(0x8, buffer, (uint)(size * coreCount), out _);
                var data2 = new SYSTEM_ProcessesOR_PERFORMANCE_INFORMATION[coreCount];
                for (int i = 0; i < coreCount; i++)
                {
                    nint ptr = nint.Add(buffer, i * size);
                    data2[i] = Marshal.PtrToStructure<SYSTEM_ProcessesOR_PERFORMANCE_INFORMATION>(ptr);
                }

                long totalIdle = 0;
                long totalKernel = 0;
                long totalUser = 0;

                for (int i = 0; i < coreCount; i++)
                {
                    totalIdle += data2[i].IdleTime - data1[i].IdleTime;
                    totalKernel += data2[i].KernelTime - data1[i].KernelTime;
                    totalUser += data2[i].UserTime - data1[i].UserTime;
                }

                long totalSystem = totalKernel + totalUser;

                double cpuUsage = (1.0 - (double)totalIdle / totalSystem) * 100;
                return Math.Round(cpuUsage, 2);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }


        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(
            int SystemInformationClass,
            nint SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength
        );

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_ProcessesOR_PERFORMANCE_INFORMATION
        {
            public long IdleTime;
            public long KernelTime;
            public long UserTime;
            public long DpcTime;
            public long InterruptTime;
            public uint InterruptCount;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public nint Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_Processes_INFORMATION
        {
            public uint NextEntryOffset;
            public uint NumberOfThreads;
            private long Reserved1;
            private long Reserved2;
            private long Reserved3;
            private long Reserved4;
            private long Reserved5;
            private long Reserved6;
            public UNICODE_STRING ImageName;
            public int BasePriority;
            public nint ProcessesId;
            public nint InheritedFromProcessesId;
            private uint HandleCount;
            private uint SessionId;
            private nuint UniqueProcessesKey;
            private nuint PeakVirtualSize;
            private nuint VirtualSize;
            private uint PageFaultCount;
            private nuint PeakWorkingSetSize;
            private nuint WorkingSetSize;
            private nuint QuotaPeakPagedPoolUsage;
            private nuint QuotaPagedPoolUsage;
            private nuint QuotaPeakNonPagedPoolUsage;
            private nuint QuotaNonPagedPoolUsage;
            private nuint PagefileUsage;
            private nuint PeakPagefileUsage;
            private nuint PrivatePageCount;
            public ulong KernelTime;
            public ulong UserTime;
            private long ReadOperationCount;
            private long WriteOperationCount;
            private long OtherOperationCount;
            private long ReadTransferCount;
            private long WriteTransferCount;
            private long OtherTransferCount;
        }

        private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
    }
}
