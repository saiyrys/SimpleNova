using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static HeuristicAnalyze.SystemWin.PEHeaderReader;

namespace HeuristicAnalyze.Interfaces.System
{
    public interface IPEHeaderReader
    {
        IMAGE_SECTION_HEADER ReadDotTextSections();

        IMAGE_SECTION_HEADER ReadDotDataSections();

        byte[] GetSectionBytes(byte[] fileData, IMAGE_SECTION_HEADER section);

        bool Is32BitHeader { get; }

        DateTime TimeStamp { get; }
    }
}
