using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.SystemWin
{
    public class NativeDllMethods
    {
        public static string[] GetExports(string ModuleFileName)
        {
            string tempCopy = Path.Combine(Path.GetTempPath(), Path.GetFileName(ModuleFileName));
            File.Copy(ModuleFileName, tempCopy, true);

            SafeFileHandle FileHandle = NativeMethods.CreateFile(
                tempCopy,
                NativeMethods.EFileAccess.GenericRead,
                NativeMethods.EFileShare.Read | NativeMethods.EFileShare.Write,
                IntPtr.Zero,
                NativeMethods.ECreationDisposition.OpenExisting,
                NativeMethods.EFileAttributes.Normal,
                IntPtr.Zero
            );

            if (FileHandle.IsInvalid)
                throw new Win32Exception();

            try
            {
                SafeFileHandle ImageHandle = NativeMethods.CreateFileMapping(
                    FileHandle,
                    IntPtr.Zero,
                    NativeMethods.FileMapProtection.PageReadonly,
                    0,
                    0,
                    IntPtr.Zero
                );
                if (ImageHandle.IsInvalid)
                    throw new Win32Exception();

                try
                {
                    IntPtr ImagePointer = NativeMethods.MapViewOfFile(
                        ImageHandle,
                        NativeMethods.FileMapAccess.FileMapRead,
                        0,
                        0,
                        UIntPtr.Zero
                    );
                    if (ImagePointer == IntPtr.Zero)
                        throw new Win32Exception();

                    try
                    {
                        IntPtr HeaderPointer = NativeMethods.ImageNtHeader(ImagePointer);
                        if (HeaderPointer == IntPtr.Zero)
                            throw new Win32Exception();

                        PEHeaderReader.IMAGE_NT_HEADERS Header = (PEHeaderReader.IMAGE_NT_HEADERS)Marshal.PtrToStructure(
                            HeaderPointer,
                            typeof(PEHeaderReader.IMAGE_NT_HEADERS)
                        );
                        if (Header.Signature != 0x00004550)// "PE\0\0" as a DWORD
                            throw new Exception(ModuleFileName + " is not a valid PE file");

                        bool is64Bit = Header.OptionalHeader64.Magic == 0x20b; // 0x20b — PE32+

                        uint exportRVA = is64Bit
                            ? Header.OptionalHeader64.DataDirectory[0].VirtualAddress
                            : Header.OptionalHeader32.DataDirectory[0].VirtualAddress;

                        IntPtr ExportTablePointer = NativeMethods.ImageRvaToVa(
                            HeaderPointer,
                            ImagePointer,
                            exportRVA,
                            IntPtr.Zero
                        );

                        if (ExportTablePointer == IntPtr.Zero)
                            throw new Win32Exception();
                        PEHeaderReader.IMAGE_EXPORT_DIRECTORY ExportTable = (PEHeaderReader.IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(
                            ExportTablePointer,
                            typeof(PEHeaderReader.IMAGE_EXPORT_DIRECTORY)
                        );

                        IntPtr NamesPointer = NativeMethods.ImageRvaToVa(
                            HeaderPointer,
                            ImagePointer,
                            ExportTable.AddressOfNames,
                            IntPtr.Zero
                        );
                        if (NamesPointer == IntPtr.Zero)
                            throw new Win32Exception();

                        NamesPointer = NativeMethods.ImageRvaToVa(
                            HeaderPointer,
                            ImagePointer,
                            (UInt32)Marshal.ReadInt32(NamesPointer),
                            IntPtr.Zero
                        );
                        if (NamesPointer == IntPtr.Zero)
                            throw new Win32Exception();

                        string[] exports = new string[ExportTable.NumberOfNames];
                        for (int i = 0; i < exports.Length; i++)
                        {
                            exports[i] = Marshal.PtrToStringAnsi(NamesPointer);
                            NamesPointer += exports[i].Length + 1;
                        }

                        return exports;
                    }
                    finally
                    {
                        if (!NativeMethods.UnmapViewOfFile(ImagePointer))
                            throw new Win32Exception();
                    }
                }
                finally
                {
                    ImageHandle.Close();
                }
            }
            finally
            {
                FileHandle.Close();
            }
        }
    }
}
