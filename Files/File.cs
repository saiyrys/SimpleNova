using Microsoft.Win32.SafeHandles;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;


namespace HeuristicAnalyze.Files
{
    // Класс для низкоуровневой работы с файлами через WinAPI
    public class File
    {
        private string name;
        private readonly string path = ""; // Полный путь до файла, который мы открываем
        public string extension;

        static long _size;// (пока не используется) размер файла, можно потом заполнить при открытии

        public string Name => name;
        public long Size => _size;
        public string Extension => extension;

        
        private static byte command_jmp = 0xe8;

        // Конструктор: получает путь до файла
        public File(string path)
        {
            this.path = path;
            _size = FileService.GetLogicalFileSize(this.path);
        }

        public string GetFileName(bool WithExtension = false)
        {
            return name = FileService.GetFileName(path,WithExtension);
        }

        public string GetExtension()
        {
            return extension = FileService.GetExtension(path);
        }

        public FileType GetFileType()
        {
            File file = new(path);
            ExtensionDeterminator exd = new(file);
            return exd.GetFileType();
        }
        /// <summary>
        /// Читает часть файла, определённую долей fraction (например, 0.5 — половина файла)
        /// </summary>
        /// <param name="fraction">Часть файла от 0 до 1, которую нужно прочитать.</param>
        /// <returns>Массив байтов с данными из файла.</returns>
        public byte[] ReadPartFile(double fraction)
        {
            // Проверяем, что fraction — корректное значение
            if (fraction <= 0 || fraction > 1)
                throw new ArgumentOutOfRangeException(nameof(fraction), "Уровень должен быть между 0 и 1");

            // Открываем файл через WinAPI функцию CreateFileW
            using SafeFileHandle handle = CreateSafeFileHandle(path);

            // Проверяем, что файл открылся корректно
            if (handle.IsInvalid)
            { 
                Console.WriteLine("Ошибка открытия фала");
                return Array.Empty<byte>();
            }

            // Вычисляем сколько байт нужно прочитать
            long bytesToRead = (long)(Size * fraction);

            if (bytesToRead > int.MaxValue)
                bytesToRead = int.MaxValue;

            // Создаём буфер для чтения
            byte[] buffer = new byte[bytesToRead];

            // Ставим указатель чтения в начало файла (смещение 0)
            if (SetFilePointer(handle, 0) == INVALID_SET_FILE_POINTER)
                throw new IOException("Ошибка установки указателя");

            // Читаем данные в буфер
            if (!ReadFileSpan(handle, buffer, out int bytesRead))
                throw new IOException("Ошибка чтения файла");

            // Если вдруг считали меньше байтов, чем планировали — уменьшаем буфер
            if (bytesRead < buffer.Length)
                Array.Resize(ref buffer, bytesRead);

            // Возвращаем прочитанные данные
            return buffer;
        }

        public async Task<byte[]> ReadPartFileAsync(double fraction)
        {
            // Проверяем корректность параметра
            if (fraction <= 0 || fraction > 1)
                throw new ArgumentOutOfRangeException(nameof(fraction), "Уровень должен быть между 0 и 1");

            // Открываем файл
            using SafeFileHandle handle = CreateSafeFileHandle(path);
            if (handle.IsInvalid)
            {
                Console.WriteLine("Ошибка открытия файла");
                return Array.Empty<byte>();
            }

            // Вычисляем размер для чтения
            long bytesToRead = (long)(Size * fraction);
            if (bytesToRead > int.MaxValue)
                bytesToRead = int.MaxValue;

            // Размер буфера для чтения (оптимально 64KB-1MB)
            const int bufferSize = 65536; // 64KB
            byte[] result = new byte[bytesToRead];
            byte[] readBuffer = new byte[bufferSize];
            long currentPosition = 0;

            // Ставим указатель в начало
            if (SetFilePointer(handle, 0) == INVALID_SET_FILE_POINTER)
                throw new IOException("Ошибка установки указателя");

            // Читаем асинхронно частями
            while (currentPosition < bytesToRead)
            {
                int bytesLeft = (int)Math.Min(bufferSize, bytesToRead - currentPosition);
                int bytesRead = 0;

                // Асинхронное чтение
                if (!ReadFileSpan(handle, readBuffer, out bytesRead) || bytesRead == 0)
                    throw new IOException("Ошибка чтения файла");

                // Копируем прочитанные данные в итоговый буфер
                Buffer.BlockCopy(readBuffer, 0, result, (int)currentPosition, bytesRead);
                currentPosition += bytesRead;
            }

            return result;
        }


        // Приватный метод: безопасно читает часть файла начиная с заданного смещения
        /// <summary>
        /// Пытается прочитать байты из файла по указанному смещению.
        /// </summary>
        public bool TryRead(long offset, Span<byte> buffer)
        {
            using SafeFileHandle handle = CreateSafeFileHandle(path);
            if (handle.IsInvalid)
                return false;

            if (SetFilePointer(handle, offset) == uint.MaxValue) // uint.MaxValue == INVALID_SET_FILE_POINTER
                return false;

            return ReadFileSpan(handle, buffer, out int bytesRead) && bytesRead == buffer.Length;
        }

        /// <summary>
        /// Создаёт безопасный файловый дескриптор для чтения файла.
        /// </summary>
        private static SafeFileHandle CreateSafeFileHandle(string filePath)
        {
            return CreateFileW(
                filePath,
                GENERIC_READ,
                FILE_SHARE_READ,
                nint.Zero,
                OPEN_EXISTING,
                FILE_FLAG_SEQUENTIAL_SCAN,
                nint.Zero
            );
        }

        /// <summary>
        /// Перемещает указатель чтения файла.
        /// </summary>
        private static uint SetFilePointer(SafeFileHandle fileHandle, long position)
        {
            int low = (int)(position & 0xFFFFFFFF);
            int high = (int)(position >> 32);

            uint result = SetFilePointer(fileHandle, low, out int highOut, FILE_BEGIN);
            if (result == uint.MaxValue && Marshal.GetLastWin32Error() != 0)
                return uint.MaxValue;

            return result;
        }

        /// <summary>
        /// Читает данные из файла в массив байтов (буфер) через низкоуровневый указатель.
        /// </summary>
        /// <param name="handle">Открытый безопасный дескриптор файла.</param>
        /// <param name="buffer">Буфер куда читаем данные.</param>
        /// <param name="bytesRead">Сколько реально байт прочитали.</param>
        /// <returns>true если чтение успешно, иначе false.</returns>
        private static unsafe bool ReadFileSpan(SafeFileHandle handle, Span<byte> buffer, out int bytesRead)
        {
            // Фиксируем буфер в памяти, чтобы его адрес не двигался во время работы сборщика мусора
            fixed (byte* ptr = buffer)
            {
                // Вызываем ReadFile WinAPI функцией
                // Передаём дескриптор файла, адрес начала буфера, длину буфера, получаем реальное количество прочитанных байт
                return ReadFile(handle, (nint)ptr, buffer.Length, out bytesRead, nint.Zero);
            }
        }


        // ----------- Константы WinAPI ------------

        public const uint GENERIC_READ = 0x80000000;              // Флаг: открыть файл для чтения
        public const uint FILE_SHARE_READ = 0x00000001;           // Флаг: разрешить другим читать
        public const uint OPEN_EXISTING = 3;                      // Флаг: открыть существующий файл
        public const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000; // Флаг: оптимизация для последовательного чтения

        public static readonly nint INVALID_HANDLE_VALUE = new nint(-1); // Указатель ошибки при открытии файла
        public const uint INVALID_SET_FILE_POINTER = 0xFFFFFFFF;             // Ошибка перемещения курсора в файле

        public const uint FILE_BEGIN = 0; // С начала файла (0 байт)

        // ----------- Импортированные функции WinAPI ------------

        // Открытие файла (широкие строки, UNICODE)
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            nint lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            nint hTemplateFile
        );

        // Чтение из файла в небезопасный IntPtr
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(
           SafeFileHandle hFile,
           nint lpBuffer,
           int nNumberOfBytesToRead,
           out int lpNumberOfBytesRead,
           nint lpOverlapped
       );

        
        // Смещает указатель позиции в файле
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SetFilePointer(
            SafeFileHandle hFile,
            int lDistanceToMove,
            out int lpDistanceToMoveHigh,
            uint dwMoveMethod
        );
    }
}

