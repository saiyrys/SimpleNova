using HeuristicAnalyze.Interfaces.Log;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Log
{
    public class Logger : ILogger
    {
        private readonly List<string> _entries = new();
        private double _score = 0.0;

        public List<string> Entries => _entries;
        public double Score => _score;

        public void Info(string message)
        {
            _entries.Add($"[{GetTimestamp()}]|INFO|{message}");
        }

        public void ExceptionInfo(string message)
        {
            _entries.Add($"[{GetTimestamp()}]|EXCEPTION|{message}");
        }

        public void Warning(string message)
        {
            _entries.Add($"[{GetTimestamp()}]|WARNING|{message}");
        }

        public void AddScore(double value, string reason)
        {
            _score += value;
            _entries.Add($"[{GetTimestamp()}]|SCORE|{value.ToString("F2", CultureInfo.InvariantCulture)}: {reason}");
        }

        public void Reset()
        {
            _entries.Clear();
            _score = 0.0;
        }

        public string ToPlainText()
        {
            var sb = new StringBuilder();
            foreach (var entry in _entries)
                sb.AppendLine(entry);
            sb.AppendLine($"[{GetTimestamp()}]|TOTAL SCORE|{_score.ToString("F2", CultureInfo.InvariantCulture)}");
            return sb.ToString();
        }

        private static string GetTimestamp()
        {
            return DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        }
    }
}
