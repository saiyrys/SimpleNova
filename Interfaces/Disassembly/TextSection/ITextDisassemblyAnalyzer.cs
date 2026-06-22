using Iced.Intel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Interfaces.Disassembly.TextSection
{
    public interface ITextDisassemblyAnalyzer
    {
        public void SearchNopAndJmp();

        public void SearchSuspiciousJMPInstruction();

        public void SearchReverseJmpStep();

        public void SearchSysCall();

        public void SearchShortCall();

        public void AnalyzeMovInstructions();
    }
}
