using HeuristicAnalyze.Files;
using HeuristicAnalyze.Helpers;
using HeuristicAnalyze.Interfaces.Log;
using HeuristicAnalyze.SystemWin;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using static HeuristicAnalyze.SystemWin.PEHeaderReader;
using File = HeuristicAnalyze.Files.File;

namespace HeuristicAnalyze.Heuristics.GeneralHeuristics
{
    public class BaseFileAnalyzer
    {
        private readonly HeuristicUtils _util = new HeuristicUtils();

        private readonly XmlDocument xmlDoc;
        private List<string[]> ImportChains;
        private HashSet<string> WhiteList;

        private readonly ILogger _logger;

        public BaseFileAnalyzer(HeuristicUtils util, ILogger logger)
        {
            _util = util;
            ImportChains = MalwareLists.GetImportChainsList();
            WhiteList = MalwareLists.GetWhiteListExtend();
            xmlDoc = new XmlDocument();
            xmlDoc.Load("minerKeyword.xml");

            _logger = logger;
        }

        public void StartAnalyze(string path)
        {
            _logger.Reset();
            File file = new File(path);

            try
            {
                _logger.Info($"→ Анализ {path}");

                if (AnalyzeTypeFile(file))
                {
                    _logger.ExceptionInfo("⛔ Тип файла — анализ остановлен");
                    return;
                }

                if (AnalyzeSizeFile(file))
                {
                    _logger.ExceptionInfo("⛔ Размер файла — анализ остановлен");
                    return;
                }

                AnalyzeFileName(file);
                AnalyzeDigSignature(path);
                AnalyzeKeyWord(file);
                FindMinerIp(file);
                CheckStartBat(file);
                SearchApiChains(file);

                if (_logger.Score >= 0.25)
                {
                    AnalyzeRsrcSection(file);
                    if (_logger.Score >= 0.30)
                        AnalyzeCountSection(file);
                    if (_logger.Score >= 0.35)
                        AnalyzeFilePath(path);
                }
            }
            catch (Exception ex)
            {
                _logger.ExceptionInfo($"Ошибка при анализе файла {path}: {ex.Message}");
            }
        }

        public List<string> GetLog() => _logger.Entries;
        public double GetScore() => _logger.Score;


        public bool AnalyzeTypeFile(File file)
        {
            if (file.GetExtension() == ".zip" || file.GetExtension() == ".rar" || file.GetExtension() == ".7z")
            {
                _logger.AddScore(0,"Обьект является архивом, открывать с осторожностью.");
                return true;
            }

            if (WhiteList.Contains(file.GetExtension().ToLower()))
            {
                _logger.AddScore(0,"Файл исключён по расширению: ");
                return true;
            }

            _logger.AddScore(0.01, $"расширение файла {file.GetExtension()}");

            return false;
        }

        public void AnalyzeFileName(File file)
        {
            string fileName = file.GetFileName(true);

            XmlNodeList? nodeList = xmlDoc.SelectNodes("//MinerProcessesesExe/Exe") ?? throw new ArgumentNullException("Список пуст");
            foreach (XmlNode node in nodeList)
            {
                if (string.IsNullOrWhiteSpace(node.InnerText))
                    continue;

                if (fileName.ToLowerInvariant() == node.InnerText.ToLowerInvariant())
                {
                    _logger.AddScore(0.1, "Подозрительное имя файла");
                }
            }

            if (AnalyzeRandomStr(fileName))
            {
                _logger.AddScore(0.1, "Рандомное имя файла");
            }
            return;
        }

        public bool AnalyzeSizeFile(File file)
        {
            var fileSize = file.Size;

            var megabyte = 1024 * 1024;

            Console.WriteLine(fileSize / 1024 + " кбайт");

            if (fileSize >= (megabyte * 350))
            {
                _logger.AddScore(0, "Большой размер файла");
                return true;
            }
                
            if (fileSize <= 512)
            {
                _logger.AddScore(0.05, "Очень маленький размер файла");
                return false;
            }

            return false;
        }

        
        public void AnalyzeDigSignature(string path)
        {
            X509Certificate2 certificate;
            try
            {
                X509Certificate theSigner = X509Certificate.CreateFromSignedFile(path);
                certificate = new X509Certificate2(theSigner);
                return;
            }
            catch
            {
                _logger.AddScore(0.1, "Отсутствует цифровая подпись");
                return;
            }
        }

        public void AnalyzeKeyWord(File file)
        {
            XmlNodeList? nodeList = xmlDoc.SelectNodes("//MinerWord/Word") ?? throw new ArgumentNullException("Список пуст");
            
            byte[] data = file.ReadPartFile(0.4);

            int match = SearchMalwareKeyWords(data, nodeList);

            if (match > 12)
            {
                double tempScore = 0.005 * match;
                if (tempScore >= 0.6) 
                    _logger.AddScore(0.1, $"Найдено {match} подозрительных слов.");
            }

            return;
        }

        public void FindMinerIp(File file)
        {
            XmlNodeList minerIp = xmlDoc.SelectNodes("//MinerIPService/IP");

            var read = file.ReadPartFile(0.75);

            int match = SearchMalwareKeyWords(read, minerIp);

            if (match > 4)
            {
                double tempScore = 0.1 * match;
                if (tempScore > 0.3) 
                    _logger.AddScore(0.1, $"Найдено {match} подозрительных IP.");
            }

            return;
        }

        public void CheckStartBat(File file)
        {
            XmlNodeList nodeList = xmlDoc.SelectNodes("//MinerCMDWord/CMD");

            var fileType = file.GetFileType();

            var read = file.ReadPartFile(1);

            int match = SearchMalwareKeyWords(read, nodeList);

            if (match > 3)
            {
                double tempScore = 0.1 * match;
                if (tempScore > 0.3) 
                    _logger.AddScore(0.1,$"Найдено {match} подозрительных слов.");
            }

            return;
        }

        public void AnalyzeRsrcSection(File file)
        {
            byte[] data = file.ReadPartFile(1);
            PEHeaderReader reader = new PEHeaderReader(data);
            IMAGE_SECTION_HEADER? rsrc = reader.ReadDotRsrcSections();

            if (rsrc == null || !rsrc.HasValue)
            {
                _logger.AddScore(0.1, ".rsrc секция отсутствует или пуста");
            }

            return;
        }

        public void AnalyzeCountSection(File file)
        {
            byte[] data = file.ReadPartFile(1);
            PEHeaderReader reader = new PEHeaderReader(data);

            var sections = reader.SectionHeaders;

            if (sections.Count < 3 || sections.Count > 20)
            {
                _logger.AddScore(0.1, "Нетипичное количество секций в PE-файле");
            }

           
            return;
        }

        public void SearchApiChains(File file)
        {
            byte[] data = file.ReadPartFile(1);

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

        

        public void AnalyzeFilePath(string path)
        {
            if (FileService.GetFolderName(path) == "%TEMP%" || FileService.GetFolderName(path) == "%APPDATA%"
                || FileService.GetFolderName(path) == "Roaming" || FileService.GetFolderName(path) == "Downloads"
                || FileService.GetFolderName(path) == "ProgramData" || FileService.GetFolderName(path) == "System32")
            {
                _logger.AddScore(0.1, $"Файл находится в подозрительном месте: {path}");
            }

            return;
        }

        private int SearchMalwareKeyWords(byte[] file, XmlNodeList nodeList = null)
        {
            int count = 0;

            if (nodeList == null)
                return 0;

            foreach (XmlNode word in nodeList)
            {
                var search = Encoding.ASCII.GetBytes(word.InnerText);
                if (_util.ContainsSequence(file, search))
                    count++;
            }

            return count;
        }

        private bool AnalyzeRandomStr(string text)
        {
            var regex = new Regex(@"\b[a-zA-Z0-9]{10,}\b");

            if (regex.IsMatch(text))
                return true;

            return false;
        }
    }
}
