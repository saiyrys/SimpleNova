using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace HeuristicAnalyze.Privelegies
{
    public class PrivilegeEnabler
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(nint ProcessesHandle, uint DesiredAccess, out nint TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(nint TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, int BufferLength, nint PreviousState, nint ReturnLength);

        [DllImport("kernel32.dll")]
        static extern nint GetCurrentProcess();

        private const int SE_PRIVILEGE_ENABLED = 0x00000002;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;

        private const string SE_BACKUP_NAME = "SeBackupPrivilege";

        [StructLayout(LayoutKind.Sequential)]
        struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public LUID Luid;
            public int Attributes;
        }

        public void EnablePrivilege()
        {
            EnableBackupPrivilege();
        }


        private void EnableBackupPrivilege()
        {
            if (!IsAdministrator())
            {
                Console.WriteLine("Не запущено от имени администратора — SeBackupPrivilege не может быть включена.");
                return;
            }

            nint tokenHandle;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tokenHandle))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            if (!LookupPrivilegeValue(null, SE_BACKUP_NAME, out LUID luid))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Luid = luid;
            tp.Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, nint.Zero, nint.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        private static bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }


    }
}
