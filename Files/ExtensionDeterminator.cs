using HeuristicAnalyze.Interfaces.Files;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using static HeuristicAnalyze.SystemWin.PEHeaderReader;

namespace HeuristicAnalyze.Files
{
    public class ExtensionDeterminator : IExtensionDeterminater
    {
        long _size;// (пока не используется) размер файла, можно потом заполнить при открытии

        public long Size => _size;

        private readonly File _file;

        public ExtensionDeterminator(File file)
        {
            _file = file;
        }

        private bool Contains_first_command(Span<byte> data)
        {
            byte[] allowedOpcodes = new byte[]
            {
                0xB8, // MOV AX, imm16
                0xB9, // MOV CX, imm16
                0xBA, // MOV DX, imm16
                0xBB, // MOV BX, imm16
                0xCD, // INT
                0xEB, // JMP short
                0xE9, // JMP near
                0xE8, // CALL
                0x68, // PUSH imm16
                0x6A, // PUSH imm8
                0x90, // NOP
            };

            // Проверяем: хотя бы половина байтов — допустимые опкоды
            int valid = 0;
            for (int i = 0; i < data.Length; i++)
            {
                if (allowedOpcodes.Contains(data[i]))
                    valid++;
            }

            return valid >= data.Length / 3; // хотя бы треть валидных команд
        }
        public bool SysDeterminater()
        {
            // Прочитаем первые 4096 байт (заголовка достаточно)
            var data = _file.ReadPartFile(0.01); // можно 0.01–0.05, зависит от реализации
            if (data.Length < 0x100)
                return false;

            // Проверка MZ сигнатуры
            if (data[0] != 'M' || data[1] != 'Z')
                return false;

            // Адрес PE-заголовка
            int peOffset = BitConverter.ToInt32(data, 0x3C);
            if (peOffset + 0x18 > data.Length)
                return false;

            // Проверка PE сигнатуры
            if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' || data[peOffset + 2] != 0 || data[peOffset + 3] != 0)
                return false;

            // Считываем Machine и Characteristics
            ushort characteristics = BitConverter.ToUInt16(data, peOffset + 22);

            // Проверяем тип заголовка (32/64)
            ushort magic = BitConverter.ToUInt16(data, peOffset + 24);
            const ushort PE32 = 0x10B;
            const ushort PE64 = 0x20B;

            ushort subsystem = 0;
            if (magic == PE32 && peOffset + 92 < data.Length)
            {
                subsystem = BitConverter.ToUInt16(data, peOffset + 68);
            }
            else if (magic == PE64 && peOffset + 108 < data.Length)
            {
                subsystem = BitConverter.ToUInt16(data, peOffset + 88);
            }
            else
            {
                return false;
            }

            // Проверки по характеристикам
            const ushort IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
            const ushort IMAGE_FILE_DLL = 0x2000;
            const ushort IMAGE_SUBSYSTEM_NATIVE = 1;

            bool isExecutable = (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0;
            bool isNotDll = (characteristics & IMAGE_FILE_DLL) == 0;
            bool isNative = subsystem == IMAGE_SUBSYSTEM_NATIVE;

            return isExecutable && isNotDll && isNative;
        }

        public bool BatDeterminater()
        {
            try
            {
                bool flag = false;
                var file = _file.ReadPartFile(0.05);

                if (file.Length == 0)
                    return false;

                string content = Encoding.ASCII.GetString(file).ToLowerInvariant();

                // Проверка наличия BAT-команд в начале
                if (content.StartsWith("@echo") || content.Contains("goto :") || content.Contains("cmd /c"))
                    return true;

                // Проверка доли команд в файле
                string[] lines = content.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                int commandLines = lines.Count(line =>
                    line.Contains("@echo") ||
                    line.StartsWith("rem") ||
                    line.StartsWith("cd ") ||
                    line.StartsWith("set ") ||
                    line.StartsWith("start ") ||
                    line.StartsWith("if ") ||
                    line.StartsWith("goto ") ||
                    line.StartsWith("pause"));

                flag = lines.Length > 0 && ((double)commandLines / lines.Length) >= 0.3;
                if (!flag)
                {
                    if (_file.GetExtension() == ".bat")
                        return true;
                }

                return flag;
            }
            catch(Exception ex)
            {
                throw new ArgumentException("Ошибка определения Bat файла" + ex.Message);
            } 
        }

        public bool BinDeterminater()
        {
            var file = _file.ReadPartFile(0.2);
            if (file.Length == 0)
                return false;

            // Явная сигнатура SP01
            if (file.Length >= 4 &&
                file[0] == 0x53 &&
                file[1] == 0x50 &&
                file[2] == 0x30 &&
                file[3] == 0x31)
                return true;

            // Проверка на "неизвестный бинарник" — мало видимых символов
            int printable = file.Count(b => (b >= 32 && b <= 126) || b is 9 or 10 or 13);
            double ratio = (double)printable / file.Length;

            return ratio < 0.3; // если файл почти полностью бинарный
        }

        public bool CmdDeterminator()
        {
            throw new NotImplementedException();
        }

        public bool ComDeterminater()
        {
            if (Size == 0 || Size > 65536)
                return false;

            if (MZDeterminater() && PEDeterminater())
                return false;

            Span<byte> header = stackalloc byte[16];
            if (!_file.TryRead(0, header))
                return false;

            if (Contains_first_command(header))
                return true;

            return false;
        }

        public bool DllDeterminator()
        {
            var file = _file.ReadPartFile(0.1); // Читаем ~10% файла

            if (file.Length < 0x40)
                return false;

            // Проверим сигнатуру MZ
            if (file[0] != 'M' || file[1] != 'Z')
                return false;

            // Получаем смещение PE-заголовка
            int peOffset = BitConverter.ToInt32(file, 0x3C);
            if (file.Length < peOffset + 24)
                return false;

            // Проверим сигнатуру PE\0\0
            if (file[peOffset] != 'P' || file[peOffset + 1] != 'E')
                return false;

            // Читаем флаг Characteristics
            ushort characteristics = BitConverter.ToUInt16(file, peOffset + 22);

            const ushort IMAGE_FILE_DLL = 0x2000;

            return (characteristics & IMAGE_FILE_DLL) != 0;
        }

        public bool DocxDeterminator()
        {
            var file = _file.ReadPartFile(0.0512);

            if (file.Length < 4)
                return false;

            if (file[0] == 0xD0 &&
                file[1] == 0xCF &&
                file[2] == 0x11 &&
                file[3] == 0xE0 &&
                file[4] == 0xA1 &&
                file[5] == 0xB1 &&
                file[6] == 0x1A &&
                file[7] == 0xE1)
            {
                return true;
            }

            return false;
        }

        public FileType GetFileType()
        {
            if (PEDeterminater())
                return FileType.EXE;
            if (ComDeterminater())
                return FileType.Script;
            /*if (BinDeterminater())
                return FileType.BIN;*/
            if (SysDeterminater())
                return FileType.SYS;
            if (BatDeterminater())
                return FileType.BAT;
            if (MZDeterminater())
                return FileType.EXE;
            /*if (TxtDeterminater())
                return FileType.txt;*/
            if (DocxDeterminator())
                return FileType.Document;
            if (PdfDeterminator())
                return FileType.PDF;
            if (PngDeterminator())
                return FileType.PNG;
            if (ZipDeterminator())
                return FileType.ZIP;
            if (DllDeterminator())
                return FileType.DLL;


            return FileType.Unknown;
        }

        public bool JpgDeterminator()
        {
            throw new NotImplementedException();
        }

        public bool MZDeterminater()
        {
            Span<byte> buffer = stackalloc byte[2]; // Выделяем стековую память на 2 байта
            if (!_file.TryRead(0, buffer))
                return false;

            return buffer[0] == 0x4D && buffer[1] == 0x5A; // 0x4D == 'M', 0x5A == 'Z'
        }

        public bool PdfDeterminator()
        {

            var file = _file.ReadPartFile(0.0512);

            if (file.Length < 4)
                return false;

            if (file[0] == 0x25 && // %
                file[1] == 0x50 && // P
                file[2] == 0x44 && // D
                file[3] == 0x46)    // F
            {
                return true;
            }

            return false;
        }

        public bool PEDeterminater()
        {
            Span<byte> mzHeader = stackalloc byte[2];
            if (!_file.TryRead(0, mzHeader) || mzHeader[0] != 0x4D || mzHeader[1] != 0x5A)
                return false; 

            Span<byte> peOffsetBuffer = stackalloc byte[4];
            if (!_file.TryRead(0x3C, peOffsetBuffer))
                return false;

            // Смещение до PE-заголовка хранится по адресу 0x3C
            int peHeaderOffset = BitConverter.ToInt32(peOffsetBuffer);

            if (peHeaderOffset <= 0 || peHeaderOffset >= Size - 4)
                return false; 

            Span<byte> peHeader = stackalloc byte[4];
            if (!_file.TryRead(peHeaderOffset, peHeader))
                return false;

           
            return peHeader[0] == (byte)'P' && peHeader[1] == (byte)'E' && peHeader[2] == 0 && peHeader[3] == 0;
        }

        public bool PngDeterminator()
        {
            var file = _file.ReadPartFile(0.0512);

            if (file.Length < 4)
                return false;

            if (file[0] == 0x89 && // .
                file[1] == 0x50 && // P
                file[2] == 0x4E && // N
                file[3] == 0x47)   // G
            {
                return true;
            }

            return false;
        }

        public bool PptxDeterminator()
        {
            throw new NotImplementedException();
        }

        /*public bool TxtDeterminater()
        {
            var file = _file.ReadPartFile(0.2);

            if (file.Length == 0)
                return false;

            int printable = 0;
            foreach (byte b in file)
            {
                if ((b >= 32 && b <= 126) || b is 9 or 10 or 13) // ASCII + таб + перевод строки
                    printable++;
            }

            double ratio = (double)printable / file.Length;

            return ratio > 0.9;
        }*/

        public bool ZipDeterminator()
        {
            var file = _file.ReadPartFile(0.0512);

            if (file.Length < 4)
                return false;

            if (file[0] == 0x50 && // P
                file[1] == 0x4B && // K
                file[2] == 0x03 && // .
                file[3] == 0x04)   // .
            {
                return true;
            }

            return false;
        }
    }
}
