using Iced.Intel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Interfaces.Disassembly.TextSection
{
    public interface IDotTextDisassembly
    {
        public List<Instruction> GetInstructions(byte[] data);


    }
}
