using HeuristicAnalyze.Files;
using HeuristicAnalyze.Helpers;
using HeuristicAnalyze.Interfaces.Files;
using HeuristicAnalyze.Interfaces.Heuristics;
using HeuristicAnalyze.Interfaces.Log;
using HeuristicAnalyze.SystemWin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Threading.Tasks;
using static System.Formats.Asn1.AsnWriter;
using File = HeuristicAnalyze.Files.File;

namespace HeuristicAnalyze.Heuristics.GeneralHeuristics
{
    public abstract class BaseSectionAnalyzer
    {
        private List<string[]> ImportChains;
        private Dictionary<string, List<string>> DllToApi;

        private readonly ILogger _logger;

        protected BaseSectionAnalyzer(ILogger logger)
        {
            ImportChains = MalwareLists.GetImportChainsList();

            DllToApi = new Dictionary<string, List<string>>()
            {
                ["kernel.dll"] = new List<string> { "VirtualAllocEx", "CreateRemoteThread" },
                ["ntdll.dll"] = new List<string> { "NtUnmapViewOfSection", "NtWriteVirtualMemory" },
                ["user32.dll"] = new List<string> { "SetWindowsHookEx" },
                ["advapi32.dll"] = new List<string> { "RegSetValueEx" }
            };

            _logger = logger;
        }

        public virtual void AnalyzeSectionOnSize(PEHeaderReader.IMAGE_SECTION_HEADER section)
        {

            if(section.SizeOfRawData > (section.VirtualSize * 2))
            {
                _logger.AddScore(0.05, "SizeOfRawData значительно превышает VirtualSize - может указывать на наличие серединного оверлея");
                return;
            }

            if(section.VirtualSize == 0 && section.SizeOfRawData != 0)
            {
                _logger.AddScore(0.05, "VirtualSize равен нулю, но SizeOfRawData имеет значение - загрузчик использует физический размер вместо виртуального");
                return;
            }

            if(section.PointerToRawData > 1073741824)
            {
                _logger.AddScore(0.05, "Высокое смещение указателя");
                return;
            }

            return;
        }

        public virtual void AnalyzeSectionEntropy(byte[] sectionBytes)
        {
            HeuristicUtils utils = new HeuristicUtils();
            double entropy = utils.CalculateEntropy(sectionBytes);

            if (entropy > 7.0)
            {
                _logger.AddScore(0.05, $"Высокая энтропия: {entropy:F2}");
                return;
            }

            if (entropy < 1.0)
            {   
                _logger.AddScore(0.05, $"Очень низкая энтропия: {entropy:F2} — возможно, подделка или нулевая секция.");
                return;
            }

            return;
        }

        public virtual PEHeaderReader.IMAGE_SECTION_HEADER GetSections(PEHeaderReader reader)
        {
            PEHeaderReader.IMAGE_SECTION_HEADER section = reader.ReadDotTextSections();

            return section;
        }
        

        public virtual void AnalyzeSection(string filePath)
        {
            HeuristicUtils utils = new HeuristicUtils();
            double score = 0.0;
            List<string> reasons = new();

            var data = ReadFileToByte(filePath);

            PEHeaderReader reader = new PEHeaderReader(data);

            var section = GetSections(reader);

            AnalyzeSectionOnSize(section);

            var sectionBytes = reader.GetSectionBytes(data, section);
            AnalyzeSectionEntropy(sectionBytes);

            SearchApiChains(filePath);

            AnalyzeDllChains();

            /*AnalyzeFilePath(filePath);*/
        }

        public virtual void SearchApiChains(string path)
        {
            var data = ReadFileToByte(path);
            double score = 0.0;
            List<string> reasons = new();

            PEHeaderReader reader = new PEHeaderReader(data);

            var imports = reader.GetApiImports(data);

            foreach (var chain in ImportChains)
            {
                if (chain.All(api => imports.Contains(api, StringComparer.OrdinalIgnoreCase)))
                {
                    _logger.AddScore(0.1, $"Найдена подозрительная связка API: {string.Join("->", chain)}");
                }
            }

            return;
        }

        public virtual void AnalyzeDllChains()
        {
            double score = 0.0;
            List<string> reasons = new();

            foreach (var chain in ImportChains)
            {
                bool chainMatch = chain.All(func =>
                    DllToApi.Values.Any(apiList => apiList.Contains(func, StringComparer.OrdinalIgnoreCase)));

                if (chainMatch)
                {
                    _logger.AddScore(0.1, $"Обнаружена подозрительная цепочка API: {string.Join("+", chain)}");
                }
            }

            return;
        }

        public virtual byte[] ReadFileToByte(string filePath)
        {
            File file = new(filePath);

            return file.ReadPartFile(1);
        }
    }
}
