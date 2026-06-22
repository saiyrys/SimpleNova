using HeuristicAnalyze.Files;
using HeuristicAnalyze.Helpers;
using HeuristicAnalyze.Heuristics.GeneralHeuristics;
using HeuristicAnalyze.Interfaces.Heuristics;
using HeuristicAnalyze.Interfaces.Log;
using HeuristicAnalyze.SystemWin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static HeuristicAnalyze.SystemWin.PEHeaderReader;
using File = HeuristicAnalyze.Files.File;

namespace HeuristicAnalyze.Heuristics.PEAnalyzer
{
    public class SysFileAnalyzer : BaseSectionAnalyzer
    {
        List<string[]> MinerChains = new();
        private readonly IHeuristicUtils _utils;
        private readonly ILogger _logger;
        public SysFileAnalyzer(IHeuristicUtils utils, ILogger logger) : base(logger)
        {
            MinerChains = MalwareLists.GetMinerChains();

            _utils = utils;
        }
        public void StartAnalyze(string filePath)
        {
           AnalyzeSection(filePath);
        }

        public override byte[] ReadFileToByte(string filePath)
        {
            return base.ReadFileToByte(filePath);
        }

        public override void SearchApiChains(string path)
        {
            var data = ReadFileToByte(path);
            PEHeaderReader reader = new PEHeaderReader(data);

            var imports = reader.GetApiImports(data);

            foreach(var chain in MinerChains)
            {
                if(chain.All(api => imports.Contains(api, StringComparer.OrdinalIgnoreCase)))
                {
                    _logger.AddScore(0.01, "Найдены подозрительные связки используемые для майнинга");
                }
            }

            return;
        }

        public void CheckDriverEntry(string path)
        {
            var data = ReadFileToByte(path);
            PEHeaderReader reader = new(data);
            bool is64Bit = reader.OptionalHeader64.Magic == 0x20b; // 0x20b — PE32+

            var dataDir = is64Bit
                ? reader.OptionalHeader64.DataDirectory[0]
                : reader.OptionalHeader32.DataDirectory[0];

            if(dataDir.Size > 0)
            {
                if(!_utils.ContainsSequence(data, Encoding.ASCII.GetBytes("DriverEntry")))
                {
                    _logger.AddScore(0.05, "В файле отсутствуют иморты");
                }
            }

            return;

        }
    }
}
