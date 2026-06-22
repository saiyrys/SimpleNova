using HeuristicAnalyze.Interfaces.Files;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Diagnostics;
using System.Collections.Concurrent;

namespace HeuristicAnalyze.Files
{
    public class FileService : IFileService
    {
        
        #region Public Methods
        public IEnumerable<string> GetFilesInDirectory(string dir, bool? includeSubdirectories = false)
        {
            var files = EnumerateFiles(dir, includeSubdirectories);
            return files;
        }

        // Синхронная версия для совместимости
        public IEnumerable<string> GetFilesInDirectoryAsync(string dir, bool includeSubdirectories)
        {
            return EnumerateFilesAsync(dir, includeSubdirectories).GetAwaiter().GetResult();
        }

        public int GetCountFileInDirectory(string dir, bool includeSubdirectories = false)
        {
            return GetFileCount(dir, includeSubdirectories);
        }

        // Асинхронная версия для максимальной производительности
        public async Task<int> GetCountFileInDirectoryAsync(string dir, bool? includeSubdirectories = false)
        {
            return await GetFileCountAsync(dir, includeSubdirectories);
        }

        public long GetFileSizeOnDisk(string path)
        {
            FileInfo info = new FileInfo(path);
            uint dummy, sectorsPerCluster, bytesPerSector;
            int result = GetDiskFreeSpaceW(info.Directory.Root.FullName, out sectorsPerCluster, out bytesPerSector, out dummy, out dummy);
            if (result == 0) throw new Win32Exception();
            uint clusterSize = sectorsPerCluster * bytesPerSector;
            uint hosize;
            uint losize = GetCompressedFileSizeW(path, out hosize);
            long size;
            size = (long)hosize << 32 | losize;
            return (size + clusterSize - 1) / clusterSize * clusterSize;
        }

        public static long GetLogicalFileSize(string path)
        {
            WIN32_FIND_DATA findData;

            nint findHandle = FindFirstFileW(path, out findData);

            if(findHandle == new nint(-1))
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error, $"Не удалось получить данные о файле: {path}");
            }

            try
            {
                return (long)findData.nFileSizeHigh << 32 | findData.nFileSizeLow;
            }
            finally
            {
                FindClose(findHandle);
            }

        }

        public static string GetFolderName(string path)
        {
            if (string.IsNullOrEmpty(path))
                return string.Empty;

            int lastIndex = path.LastIndexOf('\\');

            return path.Substring(lastIndex + 1);
        }

        public static string GetExtension(string path)
        {
            if (string.IsNullOrEmpty(path))
                return string.Empty;

            int lastDotIndex = path.LastIndexOf('.');

            if(lastDotIndex  > 0)
            {
                string extension = path.Substring(lastDotIndex);
                return extension;
            }

            return "";
        }

        public static string GetFileName(string path, bool withExtension = false)
        {
            if (string.IsNullOrEmpty(path))
                return string.Empty;

            int lastSlash = Math.Max(path.LastIndexOf('/'), path.LastIndexOf('\\'));

            string fileName = lastSlash < 0 || lastSlash == path.Length - 1
                ? path
                : path.Substring(lastSlash + 1);

            if (withExtension)
            {
                return fileName;
            }

            int dotindex = fileName.LastIndexOf('.');
            if (dotindex > 0)
                return fileName.Substring(0, dotindex);

            return fileName;
        }

        #endregion Public Methods


        #region Kernel Methods
        [DllImport("kernel32.dll")]
        static extern uint GetCompressedFileSizeW([In, MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
            [Out, MarshalAs(UnmanagedType.U4)] out uint lpFileSizeHigh);

        [DllImport("kernel32.dll", SetLastError = true, PreserveSig = true)]
        static extern int GetDiskFreeSpaceW([In, MarshalAs(UnmanagedType.LPWStr)] string lpRootPathName,
           out uint lpSectorsPerCluster, out uint lpBytesPerSector, out uint lpNumberOfFreeClusters,
           out uint lpTotalNumberOfClusters);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WIN32_FIND_DATA
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string cAlternateFileName;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool GetFileAttributesEx(string name, int fileInfoLevel, out WIN32_FIND_DATA fileData);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern nint FindFirstFileW(string lpFileName, out WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool FindNextFile(nint hFindFile, out WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FindClose(nint hFindFile);

        private static readonly nint INVALID_HANDLE_VALUE = new nint(-1);
        private const int FILE_ATTRIBUTE_DIRECTORY = 16;



        private async Task<int> GetFileCountAsync(string dir, bool? includeSubdirectories)
        {
            Queue<string> directories = new Queue<string>();
            directories.Enqueue(dir);

            int fileCount = 0;

            while (directories.Count > 0)
            {
                string currentDir = directories.Dequeue();
                string searchPattern = Path.Combine(currentDir, "*");

                var findFileData = new WIN32_FIND_DATA();
                nint hFindFile = FindFirstFileW(searchPattern, out findFileData);

                if (hFindFile == INVALID_HANDLE_VALUE)
                    continue;

                try
                {
                    do
                    {
                        if ((findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                        {
                            fileCount++;
                            continue;
                        }

                        if ((bool)includeSubdirectories &&
                            findFileData.cFileName != "." &&
                            findFileData.cFileName != "..")
                        {
                            string subDir = Path.Combine(currentDir, findFileData.cFileName);
                            directories.Enqueue(subDir);
                        }
                    }
                    while (FindNextFile(hFindFile, out findFileData));
                }
                finally
                {
                    FindClose(hFindFile);
                }
            }

            return fileCount;
        }

        private int GetFileCount(string dir, bool includeSubdirectories = false)
        {
            string searchPattern = Path.Combine(dir, "*");

            var findFileData = new WIN32_FIND_DATA();

            nint hFindFile = FindFirstFileW(searchPattern, out findFileData);
            if (hFindFile == INVALID_HANDLE_VALUE)
                throw new Exception("Directory not found: " + dir);

            int fileCount = 0;

            do
            {
                if ((findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                {
                    fileCount++;
                    continue;
                }

                if (includeSubdirectories && findFileData.cFileName != "." && findFileData.cFileName != "..")
                {
                    string subDir = Path.Combine(dir, findFileData.cFileName);
                    fileCount += GetFileCount(subDir, true);
                }
            }
            while (FindNextFile(hFindFile, out findFileData));

            FindClose(hFindFile);

            return fileCount;
        }

        private static async Task<IEnumerable<string>> EnumerateFilesAsync(string dir, bool includeSubdirectories)
        {
            ConcurrentQueue<string> directories = new ConcurrentQueue<string>();
            directories.Enqueue(dir);

            ConcurrentBag<string> files = new ConcurrentBag<string>(); // Используем ConcurrentBag для потокобезопасного добавления

            await Task.Run(() =>
            {
                Parallel.ForEach(directories, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, currentDir =>
                {
                    string searchPattern = currentDir.TrimEnd('\\') + "\\*";

                    var localFindData = new WIN32_FIND_DATA();
                    nint hFindFile = FindFirstFileW(searchPattern, out localFindData);

                    if (hFindFile == INVALID_HANDLE_VALUE)
                    {
                        Console.WriteLine($"DENIED Cannot access: {currentDir}");
                        return;
                    }

                    try
                    {
                        do
                        {
                            string fileName = localFindData.cFileName;

                            if (fileName == "." || fileName == "..")
                                continue;

                            string fullPath = Path.Combine(currentDir, fileName);

                            if ((localFindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                            {
                                files.Add(fullPath); // Просто добавляем в ConcurrentBag
                            }
                            else if (includeSubdirectories)
                            {
                                directories.Enqueue(fullPath);
                            }
                        }
                        while (FindNextFile(hFindFile, out localFindData));
                    }
                    finally
                    {
                        FindClose(hFindFile);
                    }
                });
            });

            return files;
        }


        private static IEnumerable<string> EnumerateFiles(string dir, bool? includeSubdirectories)
        {
            string searchPattern = dir.TrimEnd('\\') + "\\*";
            Console.WriteLine($"[SEARCH] {searchPattern}");

            var localFindData = new WIN32_FIND_DATA(); // <--- 🔥 Новый для каждого вызова
            nint hFindFile = FindFirstFileW(searchPattern, out localFindData);

            if (hFindFile == INVALID_HANDLE_VALUE)
            {
                Console.WriteLine($"[DENIED] Cannot access: {dir}");
                yield break;
            }

            try
            {
                do
                {
                    string fileName = localFindData.cFileName;

                    if (fileName == "." || fileName == "..")
                        continue;

                    string fullPath = Path.Combine(dir, fileName);

                    if ((localFindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                    {
                        System.Diagnostics.Debug.WriteLine($"[FILE] {fullPath}");
                        yield return fullPath;
                    }
                    else if ((bool)includeSubdirectories)
                    {
                        System.Diagnostics.Debug.WriteLine($"[DIR] {fullPath}");
                        // 🔁 Рекурсивный вызов создаст НОВУЮ переменную localFindData
                        foreach (var file in EnumerateFiles(fullPath, includeSubdirectories))
                            yield return file;
                    }
                }
                while (FindNextFile(hFindFile, out localFindData));
            }
            finally
            {
                FindClose(hFindFile);
            }
        }

        #endregion Kernel Methods
    }
}
