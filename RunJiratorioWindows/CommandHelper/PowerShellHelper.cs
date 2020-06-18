using System;
using System.IO;
using System.Management.Automation;

namespace RunJiratorioWindows.CommandHelper
{
    public static class PowerShellHelper
    {
        public static String DockerComposeFolderPath = $"{Directory.GetParent(Directory.GetCurrentDirectory()).Parent.Parent.FullName}/DockerCompose";
        public static bool ExecuteDocker(string command)
        {
            using (var ps = PowerShell.Create())
            {
                var listaReturn = ps.AddScript(command).Invoke();
                foreach (var result in listaReturn)
                {
                    if (!result.ImmediateBaseObject.ToString().Contains("Docker version"))
                    {
                        Console.WriteLine("Você precisa instalar o docker");
                        Console.ReadKey();
                        return false;
                    }
                    else if (result.ImmediateBaseObject.ToString().Contains("ERROR:"))
                    {
                        Console.WriteLine("Você precisa inicializar o docker");
                        Console.ReadKey();
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public static bool ExecuteVPN(string command)
        {
            using (var ps = PowerShell.Create())
            {
                var listaReturn = ps.AddScript(command).Invoke();
                foreach (var result in listaReturn)
                {
                    if (result.ImmediateBaseObject.ToString().Contains("Ping request could not"))
                    {
                        Console.WriteLine("Você precisa estar conectado à VPN");
                        Console.ReadKey();
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public static void Execute(string command)
        {
            using (var ps = PowerShell.Create())
            {
                var listaReturn = ps.AddScript(command).Invoke();
            }
        }
    }
}
