using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Repository.Interfaces
{
    public interface IAPITextSectionXmlKeyword
    {
        public IEnumerable<string> GetProcessesManipulation();
        public IEnumerable<string> GetExecutionCommand();
        public IEnumerable<string> GetPackingCommand();
        public IEnumerable<string> GetHookCommand();
    }
}
