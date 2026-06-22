using System.Runtime.InteropServices;
using Diagnostics.Models;

namespace Diagnostics
{
    public class GPUProcesses
    {
        private string _name;
        public string Name => _name;
        private Dictionary<int, ulong> lastGpuTimePerPid = new();
        private List<LUID> adapterLUIDs = new();

        public List<GPUProcessesInfo> GetAllGPUProcessesesWithUsage()
        {
            // Получаем LUID всех адаптеров
            adapterLUIDs = GetAllAdapterLUIDs();

            // Получаем список всех CPU процессов
            var cpuProcesseses = new CPUProcesses();
            var Processeses = cpuProcesseses.GetProcessesList();

            // Создаем словарь для хранения времени работы каждого процесса
            var gpuTimes = new Dictionary<int, ulong>();

            // Получаем начальное время работы каждого процесса
            foreach (var proc in Processeses)
            {
                try
                {
                    ulong totalTime = 0;
                    foreach (var luid in adapterLUIDs)
                    {
                        totalTime += GetGpuTime((uint)proc.PID, luid);
                    }
                    gpuTimes[proc.PID] = totalTime;
                }
                catch { }
            }

            // Ждем секунду для получения разницы времени
            Thread.Sleep(1000);

            // Создаем результат
            var result = new List<GPUProcessesInfo>();

            // Получаем конечное время и рассчитываем загрузку
            foreach (var proc in Processeses)
            {
                try
                {
                    ulong initialTime;
                    if (!gpuTimes.TryGetValue(proc.PID, out initialTime))
                        initialTime = 0;

                    ulong finalTime = 0;
                    foreach (var luid in adapterLUIDs)
                    {
                        finalTime += GetGpuTime((uint)proc.PID, luid);
                    }

                    // Рассчитываем разницу и процент загрузки
                    ulong delta = finalTime - initialTime;
                    double usage = delta / 10000.0 / 10.0;

                    // Добавляем процесс в результат
                    result.Add(new GPUProcessesInfo
                    {
                        PID = proc.PID,
                        Name = proc.Name,
                        GpuUsagePercent = usage
                    });

                    _name = proc.Name;
                }
                catch { }
            }

            return result;
        }

        public List<GPUProcessesInfo> GetGPUProcesseses()
        {
            // Получаем LUID всех адаптеров
            adapterLUIDs = GetAllAdapterLUIDs();

            var cpuProcesseses = new CPUProcesses();
            var Processeses = cpuProcesseses.GetProcessesList();

            // Делаем первый снимок
            var snapshot1 = new Dictionary<int, ulong>();
            foreach (var proc in Processeses)
            {
                try
                {
                    foreach (var luid in adapterLUIDs)
                    {
                        ulong runningTime = GetGpuTime((uint)proc.PID, luid);
                        snapshot1[proc.PID] = runningTime;
                    }
                }
                catch { }
            }

            Thread.Sleep(1000);

            var result = new List<GPUProcessesInfo>();
            // Делаем второй снимок и рассчитываем загрузку
            foreach (var proc in Processeses)
            {
                try
                {
                    ulong t1;
                    if (!snapshot1.TryGetValue(proc.PID, out t1))
                        t1 = 0;

                    ulong t2 = 0;
                    foreach (var luid in adapterLUIDs)
                    {
                        t2 += GetGpuTime((uint)proc.PID, luid);
                    }

                    ulong delta = t2 - t1;
                    double usage = delta / 10000.0 / 10.0;

                    if (usage > 0.1)
                    {
                        result.Add(new GPUProcessesInfo
                        {
                            PID = proc.PID,
                            Name = proc.Name,
                            GpuUsagePercent = usage
                        });
                    }
                }
                catch { }
            }

            return result;
        }

        // Получаем LUID всех GPU
        private List<LUID> GetAllAdapterLUIDs()
        {
            var adapters = new List<LUID>();
            D3DKMT_ADAPTERINFO info = new();
            info.cbSize = (uint)Marshal.SizeOf(info);
            info.SourceIds = new uint[16];

            int result = D3DKMTEnumAdapters(out info);
            if (result == 0)
            {
                adapters.Add(info.AdapterLuid);

                // Если есть несколько GPU, нужно добавить их
                for (int i = 1; i < info.NumOfSources; i++)
                {
                    info = new D3DKMT_ADAPTERINFO();
                    info.cbSize = (uint)Marshal.SizeOf(info);
                    info.SourceIds = new uint[16];
                    info.SourceIds[0] = info.SourceIds[i];

                    if (D3DKMTEnumAdapters(out info) == 0)
                    {
                        adapters.Add(info.AdapterLuid);
                    }
                }
            }
            return adapters;
        }

        public async Task<List<GPUProcessesInfo>> GetGPUProcessesesAsync()
        {
            var adapterLuid = await GetAdapterLuidAsync();
            var cpuProcesseses = new CPUProcesses();
            var Processeses = cpuProcesseses.GetProcessesList();

            var snapshot1 = new Dictionary<int, ulong>();

            // Используем параллельное выполнение для получения времени
            await Task.WhenAll(Processeses.Select(async proc =>
            {
                try
                {
                    ulong runningTime = await GetGpuTimeAsync((uint)proc.PID, adapterLuid);
                    snapshot1[proc.PID] = runningTime;
                }
                catch { }
            }));

            await Task.Delay(1000);

            var result = new List<GPUProcessesInfo>();

            foreach (var proc in Processeses)
            {
                try
                {
                    ulong t1;
                    if (!snapshot1.TryGetValue(proc.PID, out t1))
                        t1 = 0;

                    ulong t2 = await GetGpuTimeAsync((uint)proc.PID, adapterLuid);
                    ulong delta = t2 - t1;

                    double usage = delta / 10000.0 / 10.0;

                    if (usage > 0.1)
                    {
                        result.Add(new GPUProcessesInfo
                        {
                            PID = proc.PID,
                            Name = proc.Name,
                            GpuUsagePercent = usage
                        });
                    }
                }
                catch { }
            }

            return result;
        }

        private async Task<LUID> GetAdapterLuidAsync()
        {
            return await Task.Run(() => GetAdapterLuid());
        }

        private async Task<ulong> GetGpuTimeAsync(uint pid, LUID adapterLuid)
        {
            return await Task.Run(() => GetGpuTime(pid, adapterLuid));
        }


        public static ulong GetGpuTime(uint pid, LUID adapterLuid)
        {
            var stats = new D3DKMT_QUERYSTATISTICS
            {
                Type = D3DKMT_QUERYSTATISTICS_TYPE.D3DKMT_QUERYSTATISTICS_Processes_NODE,
                AdapterLuid = adapterLuid,
                ProcessesId = pid,
                NodeId = 0, // Обычно 0, если один GPU
                PhysicalAdapterIndex = 0,
                QueryFlags = 0
            };

            int result = D3DKMTQueryStatistics(ref stats);
            if (result != 0)
                return 0;

            return stats.QueryResult.ProcessesNodeInformation.RunningTime;
        }

        LUID GetAdapterLuid()
        {
            D3DKMT_ADAPTERINFO info = new D3DKMT_ADAPTERINFO();
            info.cbSize = (uint)Marshal.SizeOf(info);
            info.SourceIds = new uint[16];

            int result = D3DKMTEnumAdapters(out info);
            if (result != 0)
                throw new Exception("Не удалось получить адаптер");

            return info.AdapterLuid;
        }

        [DllImport("gdi32.dll")]
        public static extern int D3DKMTEnumAdapters(out D3DKMT_ADAPTERINFO info);

        [DllImport("gdi32.dll", SetLastError = true)]
        public static extern int D3DKMTQueryStatistics(ref D3DKMT_QUERYSTATISTICS stats);

        [StructLayout(LayoutKind.Sequential)]
        public struct D3DKMT_ADAPTERINFO
        {
            public uint cbSize;
            public LUID AdapterLuid;
            public uint NumOfSources;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public uint[] SourceIds;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct D3DKMT_QUERYSTATISTICS_RESULT
        {
            [FieldOffset(0)]
            public D3DKMT_QUERYSTATISTICS_Processes_NODE_INFORMATION ProcessesNodeInformation;
            // Можешь добавить другие поля, если нужно, например:
            //[FieldOffset(0)]
            //public D3DKMT_QUERYSTATISTICS_Processes_INFORMATION ProcessesInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct D3DKMT_QUERYSTATISTICS_Processes_NODE_INFORMATION
        {
            public ulong RunningTime; // Время использования GPU
            public ulong ContextSwitch;
            public ulong Preemption;
            public ulong SignaledCommandBuffer;
            public ulong SignaledPagingBuffer;
            public ulong Reserved;
        }

        public enum D3DKMT_QUERYSTATISTICS_TYPE
        {
            D3DKMT_QUERYSTATISTICS_ADAPTER = 0,
            D3DKMT_QUERYSTATISTICS_Processes = 1,
            D3DKMT_QUERYSTATISTICS_Processes_ADAPTER = 2,
            D3DKMT_QUERYSTATISTICS_Processes_NODE = 3,
            D3DKMT_QUERYSTATISTICS_NODE = 4,
            D3DKMT_QUERYSTATISTICS_VIDPNSOURCE = 5
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct D3DKMT_QUERYSTATISTICS
        {
            public D3DKMT_QUERYSTATISTICS_TYPE Type;
            public LUID AdapterLuid;
            public uint ProcessesId;
            public uint NodeId;
            public uint PhysicalAdapterIndex;
            public uint QueryFlags;

            // Union. Мы используем ProcessesInformation
            public D3DKMT_QUERYSTATISTICS_RESULT QueryResult;
        }
    }
}
