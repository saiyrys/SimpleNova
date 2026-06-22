using HeuristicAnalyze.Files;
using HeuristicAnalyze.Helpers;
using HeuristicAnalyze.Heuristics.GeneralHeuristics;
using HeuristicAnalyze.Interfaces.Heuristics;
using HeuristicAnalyze.Interfaces.Log;
using HeuristicAnalyze.SystemWin;
using Iced.Intel;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static HeuristicAnalyze.SystemWin.PEHeaderReader;
using static System.Runtime.InteropServices.JavaScript.JSType;
using File = HeuristicAnalyze.Files.File;

namespace HeuristicAnalyze.Heuristics.PEAnalyzer
{
    public class DllFileAnalyzer : BaseSectionAnalyzer
    {
        private readonly IHeuristicUtils _utils;
        private readonly ILogger _logger;

        public DllFileAnalyzer(IHeuristicUtils utils, ILogger logger) : base(logger)
        {
            _utils = utils;
            _logger = logger;
        }

        public override byte[] ReadFileToByte(string filePath)
        {
            return base.ReadFileToByte(filePath);
        }

        public void VerificationAnalyze(string path)
        {
            AnalyzeSection(path);

            AnalyzeDllFileName(path);

            // 3. Анализ подозрительного импорта
            AnalyzeImports(path);

            // 4. Анализ подозрительных экспортов
            AnalyzeSuspiciousExport(path);

            // 5. Размер файла
            CheckDllFileSize(path);
        }

        public void AnalyzeSuspiciousExport(string path)
        {
            var data = ReadFileToByte(path);

            var exports = NativeDllMethods.GetExports(path);

            if (exports == null)
                return;

            HashSet<string> suspiciousExports = new HashSet<string>
            {
                "DllMain", "Run", "Init", "Install", "Execute", "StartWorker", "WinMain"
            };

            int match = 0;
            foreach (var export in exports)
            {
                if (suspiciousExports.Contains(export))
                {
                    match++;
                    if (match >= 3)
                    {
                        _logger.AddScore(0.05, $"В файле присутствуют подозрительные экспорты в количестве: {match}");
                        return;
                    }
                }
            }
            return;
        }

        public void AnalyzeImports(string path)
        {
            var data = ReadFileToByte(path);
            HashSet<string> imports = new HashSet<string>
            {
                "LoadLibrary", "GetProcAddress", "VirtualAllocEx", "CreateRemoteThread", "WriteProcessesMemory", "Nt*"
            };

            int match = SearchSuspicious(data, imports);

            if (match >= 3)
            {   
                _logger.AddScore(0.05, $"В файле присутствуют подозрительные импорты в количестве: {match}");
                return; 
            }

            return;
        }

       
        public void AnalyzeDllFileName(string path)
        {
            File file = new(path);

            HashSet<string> nameList = new HashSet<string>
            {
                "svchost32.dll", "system32.dll", "driverhelper.dll", "nvsvc64.dll", "msvc.exe.dll"
            };

            foreach (var name in nameList)
            {
                if (file.GetFileName().Contains(name))
                {
                    _logger.AddScore(0.15, $"Найдено подозрительное имя файла: {file.Name}");
                    return;
                }
            }

            return;
        }

        public void CheckDllFileSize(string path)
        {
            File file = new(path);

            if (file.Size < 10240 && file.Size > 52428800.02)
            {
                _logger.AddScore(0.05, $"Подозрительный размер обьекта {file.Size}");
                return;
            }

            return;
        }


        private int SearchSuspicious(byte[] data, HashSet<string> lists)
        {
            int count = 0;

            foreach (var export in lists)
            {
                if (_utils.ContainsSequence(data, Encoding.ASCII.GetBytes(export)))
                {
                    count++;
                }
            }

            return count;
        }
    }
}
