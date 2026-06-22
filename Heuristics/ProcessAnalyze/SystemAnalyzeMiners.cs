using Diagnostics.Models;
using HeuristicAnalyze.Files;
using HeuristicAnalyze.Interfaces.Log;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using File = HeuristicAnalyze.Files.File;
using Diagnostics;

namespace HeuristicAnalyze.Heuristics.ProcessAnalyze
{
    public class SystemAnalyzeMiners
    {
        private readonly XmlDocument xmlDoc;

        private readonly HashSet<string> minerExe;
        private readonly HashSet<string> badParents;

        private readonly ILogger _logger;

        public SystemAnalyzeMiners(ILogger logger)
        {
            xmlDoc = new XmlDocument();
            xmlDoc.Load("minerKeyword.xml");

            minerExe = xmlDoc.SelectNodes("//MinerProcessesesExe/Exe")!
               .Cast<XmlNode>()
               .Select(n => n.InnerText.ToLowerInvariant())
               .ToHashSet();

            badParents = xmlDoc.SelectNodes("//BadParents/Parent")!
                .Cast<XmlNode>()
                .Select(n => n.InnerText.ToLowerInvariant())
                .ToHashSet();

            _logger = logger; 
        }

        public void StartAnalyze(string path)
        {
            CPUProcesses Processes = new CPUProcesses();

            AnalyzeCpuUsages(path);

            CheckProcessesesName(Processes);

/*            CheckBadParentsForProcesses(Processes);*/

            AnalyzeGpuUsages(path);
        }


        public void AnalyzeCpuUsages(string path)
        {
            File file = new File(path);

            CPUProcesses Processes = new CPUProcesses();

            var Processeses = Processes.GetProcessesList();

            foreach (var proc in Processeses)
            {
                if (proc.Name == file.GetFileName(true) && proc.CpuUsagePercent > 60)
                {
                    _logger.AddScore(0.8, "Процесс с большим потреблением ресурсов процессора");
                }
            }

            return;
        }

        public void AnalyzeGpuUsages(string path)
        {
            File file = new File(path);
            GPUProcesses Processes = new GPUProcesses();

            var Processeses = Processes.GetGPUProcesseses();

            foreach (var proc in Processeses)
            {
                if (proc.Name == file.GetFileName(true) && proc.GpuUsagePercent > 60)
                {
                    _logger.AddScore(0.8,"Процесс с большим потреблением ресурсов Видеокарты");
                }
            }

            return;
        }

        public void CheckProcessesesName(CPUProcesses Processes)
        {
            var name = Processes.Name.ToLowerInvariant();

            if (minerExe.Contains(name))
            {
                _logger.AddScore(0.2, $"Найден подозрительный процесс");
            }

            return;
        }

        /*public void CheckBadParentsForProcesses(CPUProcesseses Processes)
        {
            var ppidToName = Processes.PPID;
            if(ppidToName.TryGetValue(Processes.PPID, out var parentProc))
            {
                if (badParents.Contains(parentProc))
                {
                    _logger.AddScore(0.2, $"Найден подозрительный PPID процесс: {parentProc}");
                    return;
                }
            }
            
            return;
        }*/


    }
}
