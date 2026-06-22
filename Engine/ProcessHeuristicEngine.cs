using Diagnostics;
using HeuristicAnalyze.Heuristics.ProcessAnalyze;
using HeuristicAnalyze.Interfaces.Engine;
using HeuristicAnalyze.Log;

namespace HeuristicAnalyze.Engine
{
    public class ProcessesHeuristicEngine : IHeuristicEngine
    {
        public event Action<string>? LogMessage;
        public event Action<int, int, string>? ProgressChanged;
        public event Action<string>? FileCountingMessage;
        public event Action<string>? EndScanMessage;

        public async Task Start(string filePath, bool? includeSubDirectories)
        {
            CPUProcesses Processes = new();

            var Processeses = Processes.GetProcessesList();

            int total = Processeses.Count();
            int current = 0;
            object lockObj = new(); // для потокобезопасного счётчика
            var semaphore = new SemaphoreSlim(4); // максимум 4 одновременных анализа
            var tasks = new List<Task>();

            foreach (var proc in Processeses)
            {
                await semaphore.WaitAsync(); // ждём "свободный слот"

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var logger = new Logger(); // отдельный логгер для каждого потока
                        logger.Reset();

                        logger.Info($"→ Анализ {proc}");
                        LogMessage?.Invoke($"INFO|{proc}");

                        var analyzer = new SystemAnalyzeMiners(logger);
                        analyzer.StartAnalyze(filePath);

                        lock (lockObj)
                        {
                            current++;
                            ProgressChanged?.Invoke(current, total, proc.Name);
                        }

                        if (logger.Score >= 0.8)
                        {
                            /*_logger.Warning($"процесс {proc} подозрителен. Проверьте его внимательно.");*/
                            EndScanMessage?.Invoke($"WARNING|{proc}");
                        }

                        logger.Info($"Анализ завершён. Финальный счёт: {logger.Score:F2}");
                        LogMessage?.Invoke(logger.ToPlainText());
                    }
                    catch (Exception ex)
                    {
                        LogMessage?.Invoke($"EXCEPTION|Ошибка при анализе {proc}: {ex.Message}");
                    }
                    finally
                    {
                        semaphore.Release();
                    }

                }));
            }

            await Task.WhenAll(tasks);

            EndScanMessage?.Invoke($"END|Анализ завершён. Объектов проверено: {total} Чисто");
        }
    }
}
