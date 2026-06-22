using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Interfaces.Heuristics
{
    public interface IHeuristicUtils
    {
        public double CalculateEntropy(byte[] data);

        public double CountDictionaryWords(string text);

        public int CountRandomStr(byte[] data);

        public bool IsPackedUPX(byte[] file);

        public int CountBase64Strings(string text);

        public bool ContainsSequence(byte[] toSearch, byte[] toFind);

    }
}
