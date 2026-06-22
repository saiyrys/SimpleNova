using HeuristicAnalyze.Interfaces.Disassembly.TextSection;
using HeuristicAnalyze.SystemWin;
using Iced.Intel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Decoder = Iced.Intel.Decoder;

namespace HeuristicAnalyze.Heuristics.DisassemblyMethods.PESectionsDisassembly
{
    public class DotTextDisassembly : IDotTextDisassembly
    {
        /// <summary>
        /// Получение дизассемблированных инструкций из файла
        /// </summary>
        /// <param name="data">Байтовое представление файла</param>
        /// <returns>Список инструкций полученных из секции .text файла</returns>
        public List<Instruction> GetInstructions(byte[] data)
        {
            PEHeaderReader headerReader = new(data);

            var dotText = headerReader.ReadDotTextSections();
            var code = headerReader.GetSectionBytes(data, dotText);
            Array.Resize(ref code, (int)dotText.SizeOfRawData);

            var reader = new ByteArrayCodeReader(code);
            int entryOffset = headerReader.RvaToOffset(headerReader.OptionalHeader32.AddressOfEntryPoint);
            var decoder = Decoder.Create(headerReader.Is32BitHeader ? 32 : 64, reader);

            var instructions = new List<Instruction>();

            while (reader.CanReadByte)
            {
                decoder.Decode(out var instruction);
                if (!instruction.IsInvalid)
                    instructions.Add(instruction);

               /* Console.WriteLine(instruction);*/
            }

            return instructions; 
        }
    }
}
