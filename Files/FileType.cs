using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Files
{
    public enum FileType
    {
        EXE,   // Настоящий исполняемый (EXE, COM, BAT)
        COM,
        BAT,
        SYS,
        BIN,
        DLL,
        CMD,
        Script,       // Скрипт (BAT, CMD, VBS, PS1)
        txt,
        PDF,    // Чистый текст
        Document,     // Документ
        PPTX,
        PNG,        // Картинка, видео, музыка
        JPG,
        ZIP,      // Архив
        Unknown
    }
}
