using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Interfaces.Log
{
    public interface ILogger
    {
        public void AddScore(double value, string reason);

        public void Info(string message);

        public void ExceptionInfo(string message);

        public void Warning(string message);

        public void Reset();

        public string ToPlainText();

        double Score { get; }
        List<string> Entries { get; }
    }
}
