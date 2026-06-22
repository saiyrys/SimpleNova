using HeuristicAnalyze.Files;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Interfaces.Files
{
    public interface IExtensionDeterminater
    {
        public FileType GetFileType();

        bool ComDeterminater();

        bool MZDeterminater();

        bool PEDeterminater();

        bool BinDeterminater();

        bool DllDeterminator();

        bool BatDeterminater();

        bool CmdDeterminator();

        /*bool TxtDeterminater();*/

        bool DocxDeterminator();

        bool PptxDeterminator();

        bool PdfDeterminator();

        bool PngDeterminator();

        bool JpgDeterminator();

        bool ZipDeterminator();
    }
}
