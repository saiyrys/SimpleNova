using HeuristicAnalyze.Interfaces.Heuristics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using File = HeuristicAnalyze.Files.File;

namespace HeuristicAnalyze.Helpers
{
    public class HeuristicUtils : IHeuristicUtils
    {
        public double CalculateEntropy(byte[] data)
        {
            int[] freq = new int[256];

            foreach (byte b in data)
            {
                freq[b]++;
            }

            double entropy = 0.0;

            int len = data.Length;

            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;

                double p = (double)freq[i] / len;
                entropy -= p * Math.Log(p, 2);
            }

            return entropy;
        }

        public  double CountDictionaryWords(string text)
        {
            var words = text.Split(new[] { ' ', '\n', '\r', '\t', '.', ',', ';', ':', '\"', '\'', '\\', '/', '(', ')' }, StringSplitOptions.RemoveEmptyEntries);
            int count = 0;
            foreach (var word in words)
            {
                if (word.Length < 4) continue;
                if (Regex.IsMatch(word, @"^[a-zA-Z]{4,}$")) // можно и добавить словарь, но так быстрее
                    count++;
            }
            return (double)count / Math.Max(words.Length, 1);
        }

        public int CountRandomStr(byte[] data)
        {
            var text = Encoding.ASCII.GetString(data);
            var regex = new Regex(@"\b[a-zA-Z0-9]{10,}\b");
            return regex.Matches(text).Count;
        }

        public bool IsPackedUPX(byte[] file)
        {
            var upxSignature = new[]
            {
                Encoding.ASCII.GetBytes("UPX!"),
                Encoding.ASCII.GetBytes("UPX0"),
                Encoding.ASCII.GetBytes("UPX1"),
            };

            foreach (var sig in upxSignature)
            {
                if (ContainsSequence(file, sig))
                    return true;
            }

            return false;
        }

        public int CountBase64Strings(string text)
        {
            var regex = new Regex(@"\b[A-Za-z0-9+/]{20,}={0,2}\b");
            return regex.Matches(text).Count;
        }

        public bool ContainsSequence(byte[] toSearch, byte[] toFind)
        {
            for (var i = 0; i + toFind.Length < toSearch.Length; i++)
            {
                var allSame = true;
                for (var j = 0; j < toFind.Length; j++)
                {
                    if (toSearch[i + j] != toFind[j])
                    {
                        allSame = false;
                        break;
                    }
                }

                if (allSame)
                {
                    return true;
                }
            }

            return false;
        }

    }
}
