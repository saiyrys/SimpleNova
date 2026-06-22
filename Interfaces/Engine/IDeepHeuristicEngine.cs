using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Interfaces.Engine
{
    public interface IDeepHeuristicEngine
    {
        public (double, string) Analyze(string filePath, double totalScore);
    }
}
