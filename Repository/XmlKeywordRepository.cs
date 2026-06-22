using HeuristicAnalyze.Repository.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace HeuristicAnalyze.Repository
{
    public class XmlKeywordRepository : IKeywordRepository, IAPITextSectionXmlKeyword
    {
        private readonly XDocument _doc;

        public XmlKeywordRepository(string path)
        {
            _doc = XDocument.Load(path);
        }

        public IEnumerable<string> GetMinerProcessesNames() =>
        _doc.Descendants("Exe").Select(x => x.Value).Where(x => !string.IsNullOrWhiteSpace(x));

        public IEnumerable<string> GetStartBatKeywords() =>
            _doc.Descendants("CMD").Select(x => x.Value).Where(x => !string.IsNullOrWhiteSpace(x));

        public IEnumerable<string> GetMinerIPs() =>
            _doc.Descendants("IP").Select(x => x.Value).Where(x => !string.IsNullOrWhiteSpace(x));

        public IEnumerable<string> GetCommonMinerKeywords() =>
            _doc.Descendants("Word").Select(x => x.Value).Where(x => !string.IsNullOrWhiteSpace(x));

        public IEnumerable<string> GetProcessesManipulation() =>
            _doc.Descendants("PManipulation").Select(x => x.Value).Where(x => !string.IsNullOrWhiteSpace(x));

        public IEnumerable<string> GetExecutionCommand() =>
            _doc.Descendants("EComand").Select(x => x.Value).Where(x => !string.IsNullOrWhiteSpace(x));


        public IEnumerable<string> GetPackingCommand() =>
            _doc.Descendants("PCommand").Select(x => x.Value).Where(x => !string.IsNullOrWhiteSpace(x));


        public IEnumerable<string> GetHookCommand() =>
            _doc.Descendants("HCommand").Select(x => x.Value).Where(x => !string.IsNullOrWhiteSpace(x));

    }
}
