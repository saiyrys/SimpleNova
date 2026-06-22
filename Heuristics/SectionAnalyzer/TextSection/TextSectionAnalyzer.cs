using HeuristicAnalyze.Helpers;
using HeuristicAnalyze.Heuristics.GeneralHeuristics;
using HeuristicAnalyze.Interfaces.Log;
using HeuristicAnalyze.SystemWin;
using System.Reflection.PortableExecutable;
using System.Text;
using File = HeuristicAnalyze.Files.File;

namespace HeuristicAnalyze.Heuristics.SectionAnalyzer.TextSection
{
    public class TextSectionAnalyzer : BaseSectionAnalyzer
    {
        private List<string[]> ImportChains;
        private Dictionary<string, List<string>> DllToApi;
        private readonly ILogger _logger;

        public TextSectionAnalyzer(ILogger logger) : base(logger)
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

        public void StartAnalyze(string path)
        {
            AnalyzeSection(path);

            File file = new File(path);
            var data = file.ReadPartFile(1);

            PEHeaderReader reader = new(data);

            var section = GetSections(reader);

            AnalyzeSectionOnSize(section);

            AnalyzeExistsUpx(path);

            AnalyzeTextSectionPrivilegies(path);
        }

        public override PEHeaderReader.IMAGE_SECTION_HEADER GetSections(PEHeaderReader reader)
        {
            PEHeaderReader.IMAGE_SECTION_HEADER section = reader.ReadDotTextSections();

            return section;
        }

        public override void AnalyzeSectionOnSize(PEHeaderReader.IMAGE_SECTION_HEADER section)
        {
            double score = 0;
            string reasons = string.Empty;

            if (section.SizeOfRawData < 0x200)
            {
                _logger.AddScore(0.05, "Слишком маленькая секция text — может быть скомпрессирована или минимизирована.");
            }

            return;
        }


        public void VerificationSection(string path)
        {
            AnalyzeSection(path);
        }

        public void AnalyzeExistsUpx(string path)
        {
            HeuristicUtils util = new HeuristicUtils();
            File file = new(path);
            var data = file.ReadPartFile(0.7);

            PEHeaderReader reader = new PEHeaderReader(data);

            foreach (var section in reader.SectionHeaders)
            {
                var name = section.Section.TrimEnd('\0');
                if (name == ".UPX0" || name == ".UPX1" || name == ".UPX2")
                {
                    _logger.AddScore(0.25, "Обнаружена секция UPX: " + name);
                }
            }

            return;
        }

        public void AnalyzeTextSectionPrivilegies(string path)
        {
            File file = new(path);
            var data = file.ReadPartFile(0.7);

            PEHeaderReader reader = new PEHeaderReader(data);

            var dotText = reader.ReadDotTextSections();

            uint characteristics = (uint)dotText.Characteristics;

            if ((characteristics & 0x40000000) == 0)
            {
                _logger.AddScore(0.05, "Секция должна быть доступна для чтения (MEM_READ).");
            }

            if ((characteristics & 0x80000000) != 0)
            {
                _logger.AddScore(0.1, "Секция не должна иметь доступ к записи (MEM_WRITE).");
            }

            if ((characteristics & 0x20000000) == 0)
            {
                _logger.AddScore(0.1, "Секция .text не имеет флага выполнения (MEM_EXECUTE) — поведение необычное.");
            }

            if ((characteristics & 0x20) == 0)
            {
                _logger.AddScore(0.05, "Секция не содержит код (CNT_CODE).");
            }

            return;
        }
    }
}
