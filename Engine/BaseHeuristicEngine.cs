using HeuristicAnalyze.Files;
using HeuristicAnalyze.Helpers;
using HeuristicAnalyze.Heuristics.GeneralHeuristics;
using HeuristicAnalyze.Interfaces.Engine;
using HeuristicAnalyze.Interfaces.Log;
using HeuristicAnalyze.Log;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using File = HeuristicAnalyze.Files.File;

namespace HeuristicAnalyze.Engine
{
    public class BaseHeuristicEngine : IHeuristicEngine
    {
        private Logger _logger;
        private BaseFileAnalyzer _analyzer;
        private DllHeuristicEngine _dllAnalyzer;
        private HeuristicUtils _util;

        public BaseHeuristicEngine()
        {
            _logger = new Logger();
            _util = new HeuristicUtils();
            _analyzer = new BaseFileAnalyzer(_util, _logger);
            _dllAnalyzer = new DllHeuristicEngine(_logger);
        }

        public event Action<string>? LogMessage;
        public event Action<int, int, string>? ProgressChanged;
        public event Action<string>? FileCountingMessage;
        public event Action<string>? EndScanMessage;

        public async Task Start(string filePath, bool? includeSubDirectories = true)
        {
            FileService service = new FileService();
            var files = (bool)includeSubDirectories
                ? service.GetFilesInDirectory(filePath, true)
                : new List<string> { filePath };

            FileCountingMessage?.Invoke($"COUNTING|Идёт подсчёт файлов...");
            int total = await service.GetCountFileInDirectoryAsync(filePath, includeSubDirectories);

            int current = 0;
            object lockObj = new(); // для потокобезопасного счётчика
            var semaphore = new SemaphoreSlim(4); // максимум 4 одновременных анализа
            var tasks = new List<Task>();

            foreach (var file in files)
            {
                await semaphore.WaitAsync(); // ждём "свободный слот"

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        File f = new File(file);
                        var logger = new Logger(); // отдельный логгер для каждого потока
                        logger.Reset();

                        logger.Info($"→ Анализ {file}");
                        LogMessage?.Invoke($"INFO|{file}|{f.GetExtension()}");

                        var analyzer = new BaseFileAnalyzer(new HeuristicUtils(), logger);
                        analyzer.StartAnalyze(file);

                        
                        byte[]? data = null;

                        string filename = f.GetFileName();

                        lock (lockObj)
                        {
                            current++;
                            ProgressChanged?.Invoke(current, total, filename);
                        }

                        if (logger.Score >= 0.3)
                        {
                            data = f.ReadPartFile(1);
                            string extension = f.GetExtension()?.ToLower();

                            if (extension == ".dll")
                            {
                                var dllAnalyzer = new DllHeuristicEngine(logger);
                                dllAnalyzer.Start(file, data, logger.Score);
                            }
                            else
                            {
                                var sectionAnalyzer = new SectionHeuristicEngine(data, logger);
                                sectionAnalyzer.EndScanMessage += (msg) => EndScanMessage?.Invoke(msg);
                                sectionAnalyzer.Start(file, logger.Score);
                            }
                        }

                        logger.Info($"Анализ завершён. Финальный счёт: {logger.Score:F2}");
                        LogMessage?.Invoke($"DONE|Чисто|{file}|{logger.Score}");
                    }
                    catch (Exception ex)
                    {
                        LogMessage?.Invoke($"EXCEPTION|Ошибка при анализе {file}: {ex.Message}");
                    }
                    finally
                    {
                        semaphore.Release(); // освобождаем слот
                    }
                }));
            }

            await Task.WhenAll(tasks);

            EndScanMessage?.Invoke($"END|Анализ завершён. Объектов проверено: {total}");
        }
    }
}
