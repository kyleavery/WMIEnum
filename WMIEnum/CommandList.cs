using Microsoft.Management.Infrastructure;
using System;
using System.Collections.Generic;

namespace WMIEnum
{
    class CommandList
    {
        Dictionary<string, Action<CimSession>> commands;
        public CommandList()
        {
            commands = new Dictionary<string, Action<CimSession>>();
        }
        public void CreateCommand(Action<CimSession> action, params string[] aliases)
        {
            foreach(string a in aliases)
            {
                commands[a] = action;
            }       
        }
        public void RunCommand(string action, CimSession session)
        {
            if(commands.ContainsKey(action))
            {
                commands[action.ToLower()](session);
            }
            else
            {
                Program.Usage();
            }
        }
    }
}
