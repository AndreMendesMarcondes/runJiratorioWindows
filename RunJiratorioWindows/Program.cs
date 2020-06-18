using RunJiratorioWindows.CommandHelper;
using System;

namespace RunJiratorioWindows
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                bool hasVPN = PowerShellHelper.ExecuteVPN("ping jira.viavarejo.com.br");
                
                if (hasVPN)
                {
                    bool hasDocker = PowerShellHelper.ExecuteDocker("docker --version");
                
                    if (hasDocker)
                        ProccessExecuterHelper.Execute("docker-compose up");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.ReadKey();
            }
        }
    }
}

