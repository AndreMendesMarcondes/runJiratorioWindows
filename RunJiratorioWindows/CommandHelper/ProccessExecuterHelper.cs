using System;
using System.Diagnostics;
using System.IO;

namespace RunJiratorioWindows.CommandHelper
{
    public static class ProccessExecuterHelper
    {
        public static String DockerComposeFolderPath = $"{Directory.GetParent(Directory.GetCurrentDirectory()).Parent.Parent.FullName}/DockerCompose";
        public static String CmdPath = $@"{Environment.SystemDirectory}\cmd.exe";
        public static void Execute(string command)
        {
            using (var process = new Process())
            {
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.FileName = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
                process.StartInfo.WorkingDirectory = DockerComposeFolderPath;
                process.StartInfo.WindowStyle = ProcessWindowStyle.Normal;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardInput = true;
                process.Start();
                process.StandardInput.WriteLine(command);

                while (!process.StandardOutput.EndOfStream)
                {
                    string line = process.StandardOutput.ReadLine();
                    Console.WriteLine(line);
                    if (line.Contains("Tomcat started on port(s): 80"))
                    {
                        PowerShellHelper.Execute("explorer 'http://localhost'");
                    }
                }

                process.WaitForExit();
            }
        }
    }
}
