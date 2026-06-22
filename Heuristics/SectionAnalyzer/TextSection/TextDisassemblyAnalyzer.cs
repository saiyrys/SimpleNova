using HeuristicAnalyze.Interfaces.Disassembly.TextSection;
using HeuristicAnalyze.Interfaces.Log;
using Iced.Intel;
using System.Threading.Tasks;


namespace HeuristicAnalyze.Heuristics.SectionAnalyzer.TextSection
{
    public class TextDisassemblyAnalyzer : ITextDisassemblyAnalyzer
    {
        private readonly byte[] _data;
        private readonly IDotTextDisassembly _disassembly;
        private List<Instruction>? instructions;

        private readonly ILogger _logger;


        /// <summary>
        /// Класс содержащий методы для дизассемблирования и проверки кода в секции .text
        /// </summary>
        /// <param name="disassembly">Интерфейс дизассемблера</param>
        /// <param name="data">Байтовое представление файла</param>
        /// <param name="logger">Система вывода логов</param>
        public TextDisassemblyAnalyzer(IDotTextDisassembly disassembly,ILogger logger, byte[] data)
        {
            _data = data;
            _disassembly = disassembly;
            _logger = logger;
        }

        public void StartAnalyze()
        {
            _logger.Info("🔬 Запущен глубокий дизассемблирование .text секции");

            InitialyzeAsync();

            SearchNopAndJmp();

            SearchSuspiciousJMPInstruction();

            SearchReverseJmpStep();
            SearchSysCall();
            SearchShortCall();
            AnalyzeMovInstructions();
        }

        public void InitialyzeAsync()
        {
            instructions =  _disassembly.GetInstructions(_data);
        }



        public void FindSignature()
        {
            ReadOnlySpan<byte> data = instructions;
        }

        /// <summary>
        /// считает в .text секции количество простых nop и jmp
        /// </summary>
        public void SearchNopAndJmp()
        {
            int nopCount = 0;
            int jmpCount = 0;

            foreach (var instr in instructions)
            {
                if (instr.Mnemonic == Mnemonic.Nop)
                    nopCount++;

                if (instr.Mnemonic == Mnemonic.Jmp && instr.Op0Kind == OpKind.Register)
                {
                    jmpCount++;
                }
            }

            if (nopCount >= 11000)
            {
                _logger.AddScore(0.05, $"Большое количество No operation инструкций: {nopCount}");
            }
            if (jmpCount >= 150)
            {
                _logger.AddScore(0.01, $"Большое количество инструкция безусловного перехода {jmpCount}");
            }

            _logger.Info($"🔍 [NOP+JMP] Найдено {0} подозрительных комбинаций");

            return;
        }

        /// <summary>
        /// Ищет в .text секции подозрительные инструкции jmp
        /// </summary>
        public void SearchSuspiciousJMPInstruction()
        {
            int jmpCount = 0;
            int jmpEquals = 0;

            foreach (var instr in instructions)
            {
                if (instr.Mnemonic == Mnemonic.Jmp &&
                    instr.Op0Kind == OpKind.Register &&
                    (instr.Op0Register == Register.ESP || instr.Op0Register == Register.RSP))
                {
                    _logger.AddScore(0.2, $"Использование безусловного перехода JMP ESP");
                }

                if (instr.Mnemonic == Mnemonic.Jmp &&
                    instr.Op0Kind == OpKind.Memory &&
                    (instr.Op0Register == Register.ESP || instr.Op0Register == Register.RSP))
                {
                    _logger.AddScore(0.3, $"Использование безусловного перехода JMP ESP");
                }

                if (instr.Mnemonic == Mnemonic.Jmp &&
                    instr.NearBranchTarget == instr.IP)
                {
                    jmpCount++;
                    if (jmpCount >= 50)
                    {
                        _logger.AddScore(0.1, $"Бесконечный цикл - антипесочница");
                    }
                }

                
            }

            _logger.Info("🔍 [NOP+JMP] Подозрительные инструкции не найдены");

            return;
        }

        /// <summary>
        /// Ищет в .text секции обратные вызовы jmp
        /// </summary>
        public void SearchReverseJmpStep()
        {
            double score = 0;
            List<string> reasons = new();

            int jmpCount = 0;
            int jmpReverse = 0;
            
            for(int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].Mnemonic == Mnemonic.Jmp)
                {
                    jmpCount++;
                }

                if ((instructions[i].Mnemonic == Mnemonic.Jmp || instructions[i].Mnemonic == Mnemonic.Call) &&
                    instructions[i].NearBranchTarget < instructions[i].IP &&
                    instructions[i].IP - instructions[i].NearBranchTarget <= 1000)
                {
                    jmpReverse++;
                }
            }

            if((double)jmpReverse / instructions.Count > 0.2)
            {
                _logger.AddScore(0.1, $"Большое количество переходов назад: {jmpReverse}");
            }

            _logger.Info("🔍 [JMP + Revers] Подозрительные инструкции не найдены");

            return;
        }

        /// <summary>
        /// Ищет в .text секции связку системных выводов
        /// </summary>
        public void SearchSysCall()
        {
            int syscallCount = 0;
            int int2eCount = 0;
            int int3Count = 0;
            int retfCount = 0;
            int iretCount = 0;

            foreach (var instr in instructions)
            {
                if(instr.Mnemonic == Mnemonic.Syscall)
                    syscallCount++;
                if (instr.Mnemonic == Mnemonic.Int)
                {
                    if (instr.Immediate8 == 0x2E)
                        int2eCount++;
                    if (instr.Immediate8 == 0x3)
                        int3Count++;
                }
                if (instr.Mnemonic == Mnemonic.Retf)
                    retfCount++;
                if (instr.Mnemonic == Mnemonic.Iret)
                    iretCount++;
            }

            if (syscallCount > 3)
            {
                _logger.AddScore(0.1, $"Обнаружено {syscallCount} системных вызовов через SYSCALL");
            }

            if (int2eCount > 2)
            {
                _logger.AddScore(0.1, $"Обнаружено {int2eCount} инструкций INT 2E (обход API)");
            }

            if (int3Count > 2)
            {
                _logger.AddScore(0.1, $"Обнаружено {int3Count} точек останова (INT 3) — возможен антиотладчик");
            }

            if (retfCount > 3)
            {
                _logger.AddScore(0.1, $"Обнаружено {retfCount} инструкций RETF");
            }

            if (iretCount > 3)
            {
                _logger.AddScore(0.1, $"Обнаружено {iretCount} инструкций iRET");
            }

            _logger.Info("🔍 [Sys+Call] Подозрительные вызовы не найдены");

            return;
        }

        /// <summary>
        /// Ищет в .text секции коротки вызовы с pop
        /// </summary>
        public void SearchShortCall()
        {
            double score = 0;
            List<string> reasons = new();

            for (int i = 0; i < instructions.Count - 1; i++)
            {
                var instr = instructions[i];

                // Проверка на короткий переход от call
                if (instr.Mnemonic == Mnemonic.Call &&
                    (instr.NearBranchTarget == instr.IP - 1 ||
                     instr.NearBranchTarget == instr.IP + 2 ||
                     instr.NearBranchTarget == instr.IP + 3 ||
                     instr.NearBranchTarget == instr.IP + 4 ||
                     instr.NearBranchTarget == instr.IP + 5 ||
                     instr.NearBranchTarget == instr.IP - 2 ||
                     instr.NearBranchTarget == instr.IP - 3))
                {
                    // Смотрим следующую инструкцию
                    var next = instructions[i + 1];
                    if (next.Mnemonic == Mnemonic.Pop &&
                        next.Op0Kind == OpKind.Register)
                    {
                        _logger.AddScore(0.1, "Найдена связка короткого call + pop (техника GetPC)");
                    }
                }
            }

            _logger.Info("🔍 [Short+Cal;] короткие вызовы не найдены");

            return;
        }

        /// <summary>
        /// Ищет в .text секции связку команды mov с командами crX, sidt, cpuid, rdtsc
        /// </summary>
        public void AnalyzeMovInstructions()
        {
            int count = 0;

            foreach(var instr in instructions)
            {
                if(instr.Mnemonic == Mnemonic.Mov && instr.Op0Register == Register.CR0 ||
                    instr.Mnemonic == Mnemonic.Sidt ||
                    instr.Mnemonic == Mnemonic.Cpuid ||
                    instr.Mnemonic == Mnemonic.Rdtsc)
                {
                    count++;
                }
            }

            if (count > 0)
            {
                double add = 0.05 * count;
                if (add > 0.2) add = 0.2; // максимум
                _logger.AddScore(add, $"Найдено подозрительных инструкций антиотладки: {count}");
            }

            _logger.Info("🔍 [MOV] Подозрительные инструкции антиотладки не найдены");

            return;
        }
    }
}
