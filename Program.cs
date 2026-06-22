using HeuristicAnalyze.Engine;
using HeuristicAnalyze.Files;
using HeuristicAnalyze.Helpers;
using HeuristicAnalyze.Heuristics;
using HeuristicAnalyze.Heuristics.DisassemblyMethods.PESectionsDisassembly;
using HeuristicAnalyze.Interfaces.Engine;
using HeuristicAnalyze.Interfaces.Log;
using HeuristicAnalyze.Privelegies;
using HeuristicAnalyze.Repository;
using HeuristicAnalyze.Repository.Interfaces;
using HeuristicAnalyze.SystemWin;
using System.Text;
using static HeuristicAnalyze.SystemWin.PEHeaderReader;
using static System.Collections.Specialized.BitVector32;
using File = HeuristicAnalyze.Files.File;

namespace HeuristicAnalyze
{
    class Program
    {
        public static async Task Main(string[] args)
        {
            AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
            {
                var ex = e.ExceptionObject as Exception;
                Console.WriteLine($"[GLOBAL ERROR] {ex?.Message}");
            };

            XmlKeywordRepository xmlKeyword = new XmlKeywordRepository("minerKeyword.xml");
            PrivilegeEnabler pe = new();

            pe.EnablePrivilege();
            
            string path = "D:\\BeamNG";

/*            FileService fs = new FileService();
            HeuristicUtils util = new();


            var engine = new BaseHeuristicEngine();
            engine.Start(path, true);*/



            /*Console.WriteLine(await fs.GetCountFileInDirectoryAsync(path, true));
*/
            /*File file = new(path);

            var data = file.ReadPartFile(0.1);
            PEHeaderReader reader = new PEHeaderReader(data);

            var sections = reader.SectionHeaders;

            foreach (var section in sections)
            {
                Console.WriteLine($"Имя секции: {section.Section}");
            }
*/


        }
    }
}
