using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Interfaces.System
{
    public interface IPESectionAnalyze
    {
        public (double, string) CheckTextSectionPrivilegies(string filePath);

        public (double, string) CheckTextSectionPrivilegies(byte[] data);
    }
}
