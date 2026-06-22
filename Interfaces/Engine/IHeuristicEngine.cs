using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Interfaces.Engine
{
    public interface IHeuristicEngine
    {
        public event Action<string>? LogMessage;
        public event Action<int, int, string>? ProgressChanged;
        public event Action<string>? FileCountingMessage;
        public event Action<string>? EndScanMessage;
        public Task Start(string filePath, bool? includeSubDirectories);
    }
}
