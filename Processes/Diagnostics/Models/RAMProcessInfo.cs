using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Diagnostics.Models
{
    public class RAMProcessesInfo
    {
        public int PPID { get; set; }

        public int PID { get; set; }

        public string Name { get; set; }

        public string State { get; set; }

        public double RAMUsageMB { get; set; }
    }
}
