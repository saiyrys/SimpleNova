using HeuristicAnalyze.Interfaces.System;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace HeuristicAnalyze.SystemWin
{
    /// <summary>
    /// Считывает заголовочную информацию формата Portable Executable.
    /// Предоставляет такую информацию, как дата компиляции сборки.
    /// </summary>

    public class PEHeaderReader : IPEHeaderReader
    {
        #region File Header Structures
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public unsafe struct IMAGE_DOS_HEADER
        {      // DOS .EXE header
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;

            public fixed ushort e_res1[4]; // fixed массивы вместо ushort[]

            public ushort e_oemid;
            public ushort e_oeminfo;

            public fixed ushort e_res2[10]; // fixed массивы вместо ushort[]

            public int e_lfanew;
        }
    

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 Name;
            public UInt32 Base;
            public UInt32 NumberOfFunctions;
            public UInt32 NumberOfNames;
            public UInt32 AddressOfFunctions;     // RVA from base of image
            public UInt32 AddressOfNames;     // RVA from base of image
            public UInt32 AddressOfNameOrdinals;  // RVA from base of image
        }




        // Взял следующие 2 определения из http://www.pinvoke.net/default.aspx/Structures/IMAGE_SECTION_HEADER.html

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;

            [FieldOffset(8)]
            public UInt32 VirtualSize;

            [FieldOffset(12)]
            public UInt32 VirtualAddress;

            [FieldOffset(16)]
            public UInt32 SizeOfRawData;

            [FieldOffset(20)]
            public UInt32 PointerToRawData;

            [FieldOffset(24)]
            public UInt32 PointerToRelocations;

            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;

            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;

            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;

            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct Misc
        {
            [FieldOffset(0)]
            public uint PhysicalAddress;
            [FieldOffset(0)]
            public uint VirtualSize;
        }

        [Flags]
        public enum DataSectionFlags : uint
        {
            /// <summary>
            /// Зарезервировано для будущего использования.
            /// </summary>
            TypeReg = 0x00000000,
            /// <summary>
            /// Зарезервировано для будущего использования.
            /// </summary>
            TypeDsect = 0x00000001,
            /// <summary>
            /// Зарезервировано для будущего использования.
            /// </summary>
            TypeNoLoad = 0x00000002,
            /// <summary>
            /// Зарезервировано для будущего использования.
            /// </summary>
            TypeGroup = 0x00000004,
            /// <summary>
            /// Секция не должна быть заполнена до следующей границы. 
            /// Этот флаг устарел и заменен на IMAGE_SCN_ALIGN_1BYTES. Он действителен только для объектных файлов.
            /// </summary>
            TypeNoPadded = 0x00000008,
            /// <summary>
            /// Зарезервировано для будущего использования.
            /// </summary>
            TypeCopy = 0x00000010,
            /// <summary>
            /// Раздел содержит исполняемый код.
            /// </summary>
            ContentCode = 0x00000020,
            /// <summary>
            /// Раздел содержит инициализированные данные.
            /// </summary>
            ContentInitializedData = 0x00000040,
            /// <summary>
            /// Раздел содержит не инициализированные данные.
            /// </summary>
            ContentUninitializedData = 0x00000080,
            /// <summary>
            /// Зарезервировано для будущего использования.
            /// </summary>
            LinkOther = 0x00000100,
            /// <summary>
            /// Раздел содержит комментарии или другую информацию. Этот тип имеет секция .drectve. Он действителен только для объектных файлов.
            /// </summary>
            LinkInfo = 0x00000200,
            /// <summary>
            /// Зарезервировано для будущего использования.
            /// </summary>
            TypeOver = 0x00000400,
            /// <summary>
            /// Раздел не станет частью изображения. Это справедливо только для объектных файлов.
            /// </summary>
            LinkRemove = 0x00000800,
            /// <summary>
            /// Раздел содержит данные COMDAT.Дополнительные сведения см. в разделе 5.5.6, Секции COMDAT (только для объектов). 
            /// </summary>
            LinkComDat = 0x00001000,
            /// <summary>
            /// Сбросьте биты обработки спекулятивных исключений в записях TLB для этой секции.
            /// </summary>
            NoDeferSpecExceptions = 0x00004000,
            /// <summary>
            /// Секция содержит данные, на которые ссылается глобальный указатель (GP).
            /// </summary>
            RelativeGP = 0x00008000,
            /// <summary>
            /// Зарезервировано для будущего использования.
            /// </summary>
            MemPurgeable = 0x00020000,
            /// <summary>
            /// Зарезервировано для будущего использования.
            /// </summary>
            Memory16Bit = 0x00020000,
            /// <summary>
            /// Зарезервировано для будущего использования.
            /// </summary>
            MemoryLocked = 0x00040000,
            /// <summary>
            /// Зарезервировано для будущего использования.
            /// </summary>
            MemoryPreload = 0x00080000,
            /// <summary>
            /// Align data on a 1-byte boundary. Valid only for object files.
            /// </summary>
            Align1Bytes = 0x00100000,
            /// <summary>
            /// Align data on a 2-byte boundary. Valid only for object files.
            /// </summary>
            Align2Bytes = 0x00200000,
            /// <summary>
            /// Align data on a 4-byte boundary. Valid only for object files.
            /// </summary>
            Align4Bytes = 0x00300000,
            /// <summary>
            /// Align data on an 8-byte boundary. Valid only for object files.
            /// </summary>
            Align8Bytes = 0x00400000,
            /// <summary>
            /// Align data on a 16-byte boundary. Valid only for object files.
            /// </summary>
            Align16Bytes = 0x00500000,
            /// <summary>
            /// Align data on a 32-byte boundary. Valid only for object files.
            /// </summary>
            Align32Bytes = 0x00600000,
            /// <summary>
            /// Align data on a 64-byte boundary. Valid only for object files.
            /// </summary>
            Align64Bytes = 0x00700000,
            /// <summary>
            /// Align data on a 128-byte boundary. Valid only for object files.
            /// </summary>
            Align128Bytes = 0x00800000,
            /// <summary>
            /// Align data on a 256-byte boundary. Valid only for object files.
            /// </summary>
            Align256Bytes = 0x00900000,
            /// <summary>
            /// Align data on a 512-byte boundary. Valid only for object files.
            /// </summary>
            Align512Bytes = 0x00A00000,
            /// <summary>
            /// Align data on a 1024-byte boundary. Valid only for object files.
            /// </summary>
            Align1024Bytes = 0x00B00000,
            /// <summary>
            /// Align data on a 2048-byte boundary. Valid only for object files.
            /// </summary>
            Align2048Bytes = 0x00C00000,
            /// <summary>
            /// Align data on a 4096-byte boundary. Valid only for object files.
            /// </summary>
            Align4096Bytes = 0x00D00000,
            /// <summary>
            /// Align data on an 8192-byte boundary. Valid only for object files.
            /// </summary>
            Align8192Bytes = 0x00E00000,
            /// <summary>
            /// The section contains extended relocations.
            /// </summary>
            LinkExtendedRelocationOverflow = 0x01000000,
            /// <summary>
            /// The section can be discarded as needed.
            /// </summary>
            MemoryDiscardable = 0x02000000,
            /// <summary>
            /// The section cannot be cached.
            /// </summary>
            MemoryNotCached = 0x04000000,
            /// <summary>
            /// The section is not pageable.
            /// </summary>
            MemoryNotPaged = 0x08000000,
            /// <summary>
            /// The section can be shared in memory.
            /// </summary>
            MemoryShared = 0x10000000,
            /// <summary>
            /// The section can be executed as code.
            /// </summary>
            MemoryExecute = 0x20000000,
            /// <summary>
            /// The section can be read.
            /// </summary>
            MemoryRead = 0x40000000,
            /// <summary>
            /// The section can be written to.
            /// </summary>
            MemoryWrite = 0x80000000
        }

        #endregion File Header Structures

        #region Private Fields

        /// <summary>
        /// The DOS header
        /// </summary>
        private readonly IMAGE_DOS_HEADER dosHeader;
        /// <summary>
        /// The file header
        /// </summary>
        private IMAGE_FILE_HEADER fileHeader;
        /// <summary>
        /// The file header
        /// </summary>
        private IMAGE_NT_HEADERS _ntHeaders;
        /// <summary>
        /// Optional 32 bit file header 
        /// </summary>
        private IMAGE_OPTIONAL_HEADER32 optionalHeader32;
        /// <summary>
        /// Optional 64 bit file header 
        /// </summary>
        private IMAGE_OPTIONAL_HEADER64 optionalHeader64;
        /// <summary>
        /// Image Section headers. Number of sections is in the file header.
        /// </summary>
        private readonly IMAGE_SECTION_HEADER[] _sectionHeaders;

        #endregion Private Fields

        #region Public Methods


        /// <param name="fileData">Для проверки файла передается его байтовое представление в формате byte[]</param>
        public PEHeaderReader(byte[] data)
        {
            if (data.Length < 64)
                throw new ArgumentException("Файл слишком мал, чтобы быть PE-файлом.");

            int offset = 0;

            // DOS-заголовок
            dosHeader = ReadStruct<IMAGE_DOS_HEADER>(data, ref offset);

            // Проверка сигнатуры DOS
            if (dosHeader.e_magic != 0x5A4D) // 'MZ'
                throw new InvalidOperationException("Файл не является PE-файлом (отсутствует сигнатура MZ)");
            
            if (dosHeader.e_lfanew + 4 > data.Length)
                throw new InvalidOperationException("PE-заголовок выходит за пределы файла");

            // Переход к PE-заголовку
            offset = dosHeader.e_lfanew;

            // Чтение подписи "PE\0\0"
            uint ntHeadersSignature = BitConverter.ToUInt32(data, offset);
            if (ntHeadersSignature != 0x00004550) // 'PE\0\0'
                throw new InvalidOperationException("Файл не содержит корректной сигнатуры PE");
            offset += 4;

            // FILE HEADER
            fileHeader = ReadStruct<IMAGE_FILE_HEADER>(data, ref offset);

            // OPTIONAL HEADER (временный offset, далее мы его перепишем правильно)
            if ((fileHeader.Characteristics & 0x0100) != 0)
            {
                optionalHeader32 = ReadStruct<IMAGE_OPTIONAL_HEADER32>(data, ref offset);
            }
            else
            {
                optionalHeader64 = ReadStruct<IMAGE_OPTIONAL_HEADER64>(data, ref offset);
            }

            // ⚠️ ВАЖНО: Правильный offset для секций — не полагайся на Marshal.SizeOf
            offset = dosHeader.e_lfanew + 4 + Marshal.SizeOf<IMAGE_FILE_HEADER>() + fileHeader.SizeOfOptionalHeader;

            // Считывание заголовков секций
            _sectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int i = 0; i < _sectionHeaders.Length; i++)
            {
                _sectionHeaders[i] = ReadStruct<IMAGE_SECTION_HEADER>(data, ref offset);
            }
        }

        private static T ReadStruct<T>(byte[] data, ref int offset) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            if (offset + size > data.Length)
                throw new ArgumentOutOfRangeException("Невозможно прочитать структуру, выход за пределы массива");

            IntPtr ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.Copy(data, offset, ptr, size);
                T result = Marshal.PtrToStructure<T>(ptr);
                offset += size;
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        private static string ReadNullTerminatedString(byte[] data, int offset)
        {
            if (offset < 0 || offset >= data.Length)
            {
                Console.WriteLine($"ReadNullTerminatedString: Offset {offset} вне диапазона");
                return string.Empty;
            }

            int length = 0;
            while (offset + length < data.Length && data[offset + length] != 0)
            {
                length++;
            }

            // Если строка обрывается без null-терминатора — логируем
            if (offset + length >= data.Length)
            {
                Console.WriteLine("ReadNullTerminatedString: Строка не закончена null-терминатором, досчитали до конца буфера.");
            }

            return Encoding.ASCII.GetString(data, offset, length);
        }

        /// <summary>
        /// Gets the header of the .NET assembly that called this function
        /// </summary>
        /// <returns></returns>
        public static PEHeaderReader GetCallingAssemblyHeader()
        {
            // Get the path to the calling assembly, which is the path to the
            // DLL or EXE that we want the time of
            byte[] fileData = Array.Empty<byte>();

            // Get and return the timestamp
            return new PEHeaderReader(fileData);
        }

        /// <summary>
        /// Gets the header of the .NET assembly that called this function
        /// </summary>
        /// <returns></returns>
        public static PEHeaderReader GetAssemblyHeader()
        {
            // Get the path to the calling assembly, which is the path to the
            // DLL or EXE that we want the time of
            byte[] fileData = Array.Empty<byte>();

            // Get and return the timestamp
            return new PEHeaderReader(fileData);
        }



        public int RvaToOffset(uint rva)
        {
            // Проверка входных данных
            if (SectionHeaders == null || SectionHeaders.Count == 0)
                throw new InvalidOperationException("Section headers are not initialized");

            // Проверка корректности RVA
            if (rva == 0)
                return 0; // RVA 0 обычно соответствует нулевому смещению

            // Проверка каждого раздела
            foreach (var section in SectionHeaders)
            {
                // Проверка корректности данных раздела
                if (section.VirtualAddress == 0 || section.PointerToRawData == 0)
                    continue; // Пропускаем некорректные разделы

                uint start = section.VirtualAddress;
                uint end = start + Math.Max(section.SizeOfRawData, section.VirtualSize);

                // Проверка диапазона с учетом возможных переполнений
                if (rva >= start && rva < end)
                {
                    // Дополнительная проверка на переполнение
                    if (rva - start > int.MaxValue || section.PointerToRawData > int.MaxValue)
                        throw new OverflowException("Calculated offset exceeds int range");

                    return (int)(rva - start + section.PointerToRawData);
                }
            }

            // Добавляем дополнительную проверку для случая, когда RVA может находиться в области между разделами
            if (rva >= SectionHeaders.Last().VirtualAddress + SectionHeaders.Last().VirtualSize)
            {
                // Возможно, это данные после последнего раздела
                return (int)(rva - SectionHeaders.Last().VirtualAddress + SectionHeaders.Last().PointerToRawData);
            }

            // Если RVA все еще не найден
            throw new ArgumentException($"RVA {rva} not found in any section");
        }

        public List<string> GetApiImports(byte[] data)
        {
            var imports = new List<string>();

            IMAGE_DATA_DIRECTORY importDirectory = Is32BitHeader
                ? OptionalHeader32.ImportTable
                : OptionalHeader64.ImportTable;

            uint importRva = importDirectory.VirtualAddress;
            uint importSize = importDirectory.Size;

            if (importRva == 0 || importSize == 0)
            {
                Console.WriteLine("Import Directory отсутствует или пуст.");
                return imports;
            }

            int importOffset = RvaToOffset(importRva);
            if (importOffset < 0 || importOffset >= data.Length)
            {
                Console.WriteLine("Import Table выходит за пределы файла.");
                return imports;
            }

            while (true)
            {
                int tempOffset = importOffset;
                var descriptor = ReadStruct<IMAGE_IMPORT_DESCRIPTOR>(data, ref importOffset);

                if (descriptor.OriginalFirstThunk == 0 && descriptor.FirstThunk == 0)
                    break;

                int nameOffset = RvaToOffset(descriptor.Name);
                if (nameOffset < 0 || nameOffset >= data.Length)
                    break;

                string dllName = ReadNullTerminatedString(data, nameOffset);

                uint thunkRva = descriptor.OriginalFirstThunk != 0
                    ? descriptor.OriginalFirstThunk
                    : descriptor.FirstThunk;

                int thunkOffset = RvaToOffset(thunkRva);
                if (thunkOffset < 0 || thunkOffset >= data.Length)
                    continue;

                while (true)
                {
                    if (thunkOffset >= data.Length)
                        break;

                    ulong thunkData;

                    if (Is32BitHeader)
                    {
                        if (thunkOffset + 4 > data.Length)
                            break;

                        thunkData = BitConverter.ToUInt32(data, thunkOffset);
                        thunkOffset += 4;
                    }
                    else
                    {
                        if (thunkOffset + 8 > data.Length)
                            break;

                        thunkData = BitConverter.ToUInt64(data, thunkOffset);
                        thunkOffset += 8;
                    }

                    if (thunkData == 0)
                        break;

                    if ((thunkData & 0x8000000000000000) == 0)
                    {
                        uint hintRva = (uint)(thunkData & 0x7FFFFFFF);
                        int hintOffset = RvaToOffset(hintRva);

                        if (hintOffset < 0 || hintOffset + 2 >= data.Length)
                            break;

                        string funcName = ReadNullTerminatedString(data, hintOffset + 2);
                        imports.Add(funcName);
                    }
                }
            }

            return imports;
        }

        /// <summary>
        /// Считывает блок из файла и преобразует его в struct
        /// тип, указанный параметром шаблона
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="reader"></param>
        /// <returns></returns>
        public static T FromBinaryReader<T>(BinaryReader reader)
        {
            // Read in a byte array
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            // Pin the managed memory while, copy it out the data, then unpin it
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }


        public IMAGE_SECTION_HEADER ReadDotTextSections()
        {
            if (SectionHeaders == null || SectionHeaders.Count == 0)
            {
                throw new InvalidOperationException("Файл не содержит секций. Возможно, это не PE-файл.");
            }

            var textSection = SectionHeaders.FirstOrDefault(section =>
               section.Section.TrimEnd('\0') == ".text" || section.Section.TrimEnd('\0') == "text");

            if (textSection.Equals(default(IMAGE_SECTION_HEADER)))
                throw new InvalidOperationException(".text секция не найдена");

            return textSection;
        }

        public IMAGE_SECTION_HEADER ReadDotDataSections()
        {
            var dataSections = SectionHeaders.FirstOrDefault(section =>
            section.Section.TrimEnd('\0') == ".data");

            /*if (textSection.Equals(default(IMAGE_SECTION_HEADER)))
            {
                Console.WriteLine("Секция.text не найдена.");
                return null;
            }*/

            return dataSections;
        }

        public IMAGE_SECTION_HEADER? ReadDotRsrcSections()
        {
            if (SectionHeaders == null || SectionHeaders.Count == 0)
            {
                throw new InvalidOperationException("Файл не содержит секций.");
            }

            var rsrcSections = SectionHeaders.FirstOrDefault(section =>
            section.Section.TrimEnd('\0') == ".rsrc");

            return rsrcSections.Equals(default(IMAGE_SECTION_HEADER)) ? null : rsrcSections;
        }

        /// <summary>
        /// Преобразует секцию PE файла в байтовое представление
        /// </summary>
        /// <param name="fileData">Файл, который анализируется</param>
        /// <param name="section">Секция, которая будет преобразована в байтовое представление</param>
        /// <returns>Возврат байтового представления секции.</returns>
        public byte[] GetSectionBytes(byte[] fileData, IMAGE_SECTION_HEADER section)
        {
            int rawDataP = (int)section.PointerToRawData;
            int rawDataS = (int)section.SizeOfRawData;

            // Защита от выхода за границы файла
            if (rawDataP < 0 || rawDataS < 0 || rawDataP + rawDataS > fileData.Length)
            {
                Console.WriteLine(nameof(section), "Размер или смещение секции выходят за пределы файла. Файл повреждён или подделан.");
                return null;
            }

            byte[] textBytes = new byte[rawDataS];
            Array.Copy(fileData, rawDataP, textBytes, 0, rawDataS);

            return textBytes;
        }

        #endregion Public Methods

        #region Properties

        /// <summary>
        /// Gets if the file header is 32 bit or not
        /// </summary>
        public bool Is32BitHeader
        {
            get
            {
                ushort IMAGE_FILE_32BIT_MACHINE = 0x0100;
                return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
            }
        }

        /// <summary>
        /// Gets the file header
        /// </summary>
        public IMAGE_FILE_HEADER FileHeader
        {
            get
            {
                return fileHeader;
            }
        }

        /// <summary>
        /// Gets the optional header
        /// </summary>
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader32
        {
            get
            {
                return optionalHeader32;
            }
        }

        /// <summary>
        /// Gets the optional header
        /// </summary>
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader64
        {
            get
            {
                return optionalHeader64;
            }
        }

        public IList<IMAGE_SECTION_HEADER> SectionHeaders
        {
            get
            {
                return _sectionHeaders;
            }
        }

        /// <summary>
        /// Gets the timestamp from the file header
        /// </summary>
        public DateTime TimeStamp
        {
            get
            {
                // Timestamp is a date offset from 1970
                DateTime returnValue = new DateTime(1970, 1, 1, 0, 0, 0);

                // Add in the number of seconds since 1970/1/1
                returnValue = returnValue.AddSeconds(fileHeader.TimeDateStamp);
                // Adjust to local timezone
                returnValue += TimeZone.CurrentTimeZone.GetUtcOffset(returnValue);

                return returnValue;
            }
        }

        #endregion Properties
    }
}

