using HeuristicAnalyze.Helpers;
using HeuristicAnalyze.Heuristics.PEAnalyzer;
using HeuristicAnalyze.Log;

namespace HeuristicAnalyze.Engine
{
    public class DllHeuristicEngine
    {
        private Logger _logger;
        private byte[]? _data;
        private readonly DllFileAnalyzer _analyzer;
        private HeuristicUtils _util;

        public DllHeuristicEngine(Logger logger)
        {
            _logger = logger;
            _util = new HeuristicUtils();
            _analyzer = new DllFileAnalyzer(_util, logger);
        }

        public void Start(string file, byte[]? data, double score)
        {
            try
            {
                _data = data;
                _logger.Info($"Запущен анализ файла: {file}");

                // Базовый DLL-анализ
                _analyzer.VerificationAnalyze(file);

                // При необходимости запустить углублённый анализ секций
                if (score >= 0.4 && _data != null)
                {
                    var sectionAnalyzer = new SectionHeuristicEngine(_data, _logger);
                    sectionAnalyzer.Start(file, score);
                }

                _logger.Info($"Анализ завершён. Финальный счёт: {_logger.Score:F2}");
                Console.WriteLine(_logger.ToPlainText());
            }
            catch (Exception ex)
            {
                _logger.ExceptionInfo($"Ошибка при анализе файла {file}: {ex.Message}");
            }
        }
    }
}
