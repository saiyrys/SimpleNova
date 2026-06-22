using HeuristicAnalyze.Helpers;
using HeuristicAnalyze.Heuristics.DisassemblyMethods.PESectionsDisassembly;
using HeuristicAnalyze.Heuristics.SectionAnalyzer.TextSection;
using HeuristicAnalyze.Interfaces.Engine;
using HeuristicAnalyze.Log;

namespace HeuristicAnalyze.Engine
{
    public class SectionHeuristicEngine : IHeuristicEngine
    {
        private readonly Logger _logger;
        private readonly TextSectionAnalyzer _analyzer;
        private readonly TextDisassemblyAnalyzer _disAnalyzer;
        private readonly DotTextDisassembly _disassembly;
        private readonly HeuristicUtils _util;

        public SectionHeuristicEngine(byte[] data, Logger logger)
        {
            _logger = logger;
            _util = new HeuristicUtils();
            _disassembly = new DotTextDisassembly();

            _disAnalyzer = new TextDisassemblyAnalyzer(_disassembly, logger, data);
            _analyzer = new TextSectionAnalyzer(logger);
        }

        public event Action<string>? LogMessage;
        public event Action<int, int, string>? ProgressChanged;
        public event Action<string>? FileCountingMessage;
        public event Action<string>? EndScanMessage;

        public void Start(string file, double score)
        {
            try
            {
                _logger.Info($"▶ Секционный анализ .text начат: {file}");

                double currentScore = score;

                // Статический анализ секции .text
                _analyzer.StartAnalyze(file);
                currentScore += _logger.Score;

                // Глубокий дизассемблирование .text, если балл достаточно высокий
                if (currentScore >= 0.4)
                {
                    _disAnalyzer.StartAnalyze();
                }

                // Теперь смотрим на финальный score и выводим UI-сообщение
                if (currentScore >= 1.0)
                {
                    // Вредоносный файл
                    _logger.Warning($"Файл {file} определён как ВРЕДОНОСНЫЙ!");
                    EndScanMessage?.Invoke($"WARNING|{file}|High|{currentScore}");
                    return;
                }
                else if (currentScore >= 0.8)
                {
                    // Подозрительный файл
                    _logger.Warning($"Файл {file} подозрителен. Проверьте его внимательно.");
                    EndScanMessage?.Invoke($"WARNING|{file}|Medium|{currentScore}");
                    return;
                }
                else
                {
                    _logger.Info($"✅ Секционный анализ завершён. Балл: {_logger.Score:F2}");
                    LogMessage?.Invoke($"DONE|Чисто|{file}|{_logger.Score}");
                    return; 
                }
            }
            catch (Exception ex)
            {
                _logger.ExceptionInfo($"❌ Ошибка в секционном анализе файла {file}: {ex.Message}");
            }
        }

        public Task Start(string filePath, bool? includeSubDirectories)
        {
            throw new NotImplementedException();
        }
    }
}
