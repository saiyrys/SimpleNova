using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Interfaces.Files
{
    public interface IFileService
    {
        IEnumerable<string> GetFilesInDirectory(string dir, bool? includeSubdirectories = false);

        public Task<int> GetCountFileInDirectoryAsync(string dir, bool? includeSubdirectorie = false);

        static long GetFileSizeOnDisk(string path) => 0;

        static long GetLogicalFileSize(string path) => 0;

        static string GetFileName(string path, bool withExtension = false) => "Название отсутствует";
    }
}
