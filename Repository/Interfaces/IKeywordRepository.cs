using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Repository.Interfaces
{
    public interface IKeywordRepository
    {
        IEnumerable<string> GetMinerProcessesNames();
        IEnumerable<string> GetStartBatKeywords();
        IEnumerable<string> GetMinerIPs();
        IEnumerable<string> GetCommonMinerKeywords();
    }
}
