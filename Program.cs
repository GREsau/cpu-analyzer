using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Samples.Debugging.MdbgEngine;

using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Samples.Debugging.CorDebug;
using Microsoft.Web.Administration;

namespace cpu_analyzer {

    class ThreadSnapshotStats {

        public long TotalKernelTime { get; set; }
        public long TotalUserTime { get; set; }
        public int ThreadId { get; set; } 

        public List<string> CommonStack { get; set; }

        public static ThreadSnapshotStats FromSnapshots(IEnumerable<ThreadSnapshot> snapshots) {
            var stats = new ThreadSnapshotStats();

            stats.ThreadId = snapshots.First().Id;
            stats.TotalKernelTime = snapshots.Last().KernelTime - snapshots.First().KernelTime;
            stats.TotalUserTime = snapshots.Last().UserTime - snapshots.First().UserTime;

            stats.CommonStack = snapshots.First().StackTrace.ToList();

           
            foreach (var stack in snapshots.Select(_ => _.StackTrace.ToList())) {
                while (stats.CommonStack.Count > stack.Count) {
                    stats.CommonStack.RemoveAt(0); 
                }

                while (stats.CommonStack.Count > 0 && stack.Count > 0 && stats.CommonStack[0] != stack[0]) {
                    stats.CommonStack.RemoveAt(0);
                    stack.RemoveAt(0);
                }
            }

            return stats;
        } 

    } 

    class ThreadSnapshot {

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool GetThreadTimes(IntPtr handle, out long creation, out long exit, out long kernel, out long user);


        private  ThreadSnapshot ()
	    {
	    }

        public int Id { get; set; }
        public DateTime Time { get; set; }
        public long KernelTime { get; set; }
        public long UserTime { get; set; }

        public List<string> StackTrace {get; set;}

        static MD5CryptoServiceProvider md5Provider = new MD5CryptoServiceProvider();

        public static Guid GetMD5(string str)
        {
            lock (md5Provider)
            {
                return new Guid(md5Provider.ComputeHash(Encoding.Unicode.GetBytes(str)));
            }
        }

        public IEnumerable<Tuple<Guid, string>> StackHashes
        {
            get 
            {
                var rval = new List<Tuple<Guid, string>>();

                var trace = new List<string>();

                foreach (var item in ((IEnumerable<string>)StackTrace).Reverse())
                {
                    trace.Insert(0, item);
                    var traceString = string.Join(Environment.NewLine, trace);
                    yield return Tuple.Create(GetMD5(traceString), traceString);
                }
            }
        }

        public static ThreadSnapshot GetThreadSnapshot(MDbgThread thread) {
            var snapshot = new ThreadSnapshot();

            snapshot.Id = thread.Id;

            long creation, exit, kernel, user;
            GetThreadTimes(thread.CorThread.Handle, out creation, out exit, out kernel, out user);

            snapshot.KernelTime = kernel;
            snapshot.UserTime = user;
            snapshot.StackTrace = new List<string>();

			try
			{
				foreach (var frame in thread.Frames)
				{
					try
					{
						snapshot.StackTrace.Add(frame.Function.FullName);
					}
					catch
					{
						// no frame, so ignore
					}
				}
			}
			catch
			{
				// ignore the "cannot attach to thred" errors, we can't do anything about it, but leaving unhandled destroys the whole w3wp in production :(
			}

            return snapshot;
        }
    }

    static class Program {

        enum ParseState { 
            Unknown, Samples, Interval
        }

        static void Usage() {
            Console.WriteLine("Usage: cpu-analyzer AppPoolName|ProcessName|PID [options]");
            Console.WriteLine();
            Console.WriteLine("  /S     indicates how many samples to take (default:10)");
            Console.WriteLine("  /I     the interval between samples in milliseconds (default:1000)");
            Console.WriteLine("");
            Console.WriteLine("Example: cpu-analyzer aspnet_wp /s 60 /i 500");
            Console.WriteLine("         Take 60 samples once every 500 milliseconds");
           
        }

        static void Main(string[] args) {

            if (args.Length < 1) {
                Usage();
                return;
            }

            var samples = 10;
            var sampleInterval = 1000;


            var state = ParseState.Unknown;
            foreach (var arg in args.Skip(1)) {
                switch (state) {
                    case ParseState.Unknown:
                        if (arg.ToLower() == "/s") {
                            state = ParseState.Samples;
                        } else if (arg.ToLower() == "/i") {
                            state = ParseState.Interval;
                        } else {
                            Usage();
                            return;
                        }
                        break;
                    case ParseState.Samples:
                        if (!int.TryParse(arg, out samples)) {
                            Usage();
                            return;
                        }
                        state = ParseState.Unknown;
                        break;
                    case ParseState.Interval:
                        if (!int.TryParse(arg, out sampleInterval)) {
                            Usage();
                            return;
                        }
                        state = ParseState.Unknown;
                        break;
                    default:
                        break;
                }
            }

            var pidOrProcess = args[0]; 

          
            var stats = new Dictionary<int, List<ThreadSnapshot>>();
            var debugger = new MDbgEngine();
            var pid = GetPid(pidOrProcess);
            if (!pid.HasValue)
            {
                return;
            }

            MDbgProcess attached = null;
            try
            {
                var attachVersion = FindAttachVersion(pid.Value);
                if (attachVersion == null)
                {
                    return;
                }
                Console.WriteLine($"Attaching to process {pid} using version {attachVersion}...");
                attached = debugger.Attach(pid.Value, attachVersion);
            } catch(Exception e) {
                Console.WriteLine("Error: failed to attach to process: " + e);
                return;
            }

            attached.Go().WaitOne();

            for (var i = 0; i < samples; i++) {

                foreach (MDbgThread thread in attached.Threads) {
                    var snapshot = ThreadSnapshot.GetThreadSnapshot(thread);
                    List<ThreadSnapshot> snapshots;
                    if (!stats.TryGetValue(snapshot.Id, out snapshots)) {
                        snapshots = new List<ThreadSnapshot>();
                        stats[snapshot.Id] = snapshots;
                    }

                    snapshots.Add(snapshot);
                }

                attached.Go();
                Thread.Sleep(sampleInterval);
                attached.AsyncStop().WaitOne();
            }
            
            attached.Detach().WaitOne();

            // perform basic analysis to see which are the top N stack traces observed, 
            //  weighted on cost 

            var costs = new Dictionary<Guid,long>();
            var stacks = new Dictionary<Guid, string>();

            foreach (var stat in stats.Values)
            {
                long prevTime = -1;
                foreach (var snapshot in stat)
                {
                    var time = snapshot.KernelTime + snapshot.UserTime;
                    if (prevTime != -1)
                    {
                        foreach (var tuple in snapshot.StackHashes)
                        {
                            if (costs.ContainsKey(tuple.Item1))
                            {
                                costs[tuple.Item1] += time - prevTime;
                            }
                            else
                            {
                                costs[tuple.Item1] = time - prevTime;
                                stacks[tuple.Item1] = tuple.Item2;
                            }
                        }
                    }
                    prevTime = time;
                }
            }

            Console.WriteLine("Most expensive stacks");
            Console.WriteLine("------------------------------------");
            foreach (var group in costs.OrderByDescending(p => p.Value).GroupBy(p => p.Value))
            {
                var stacksToShow = new List<string>();

                foreach (var pair in group.OrderByDescending(p => stacks[p.Key].Length))
                {
                    if (!stacksToShow.Any(s => s.Contains(stacks[pair.Key])))
                    {
                        stacksToShow.Add(stacks[pair.Key]);
                    }
                }

                foreach (var stack in stacksToShow)
                {
                    Console.WriteLine(stack);
                    Console.WriteLine("===> Cost ({0})", group.Key);
                    Console.WriteLine();
                }
            }


            var offenders = stats.Values
               .Select(_ => ThreadSnapshotStats.FromSnapshots(_))
               .OrderBy(stat => stat.TotalKernelTime + stat.TotalUserTime)
               .Reverse();

            foreach (var stat in offenders) {
                Console.WriteLine("------------------------------------");
                Console.WriteLine(stat.ThreadId);
                Console.WriteLine("Kernel: {0} User: {1}", stat.TotalKernelTime, stat.TotalUserTime);
                foreach (var method in stat.CommonStack) {
                    Console.WriteLine(method);
                }
                Console.WriteLine("Other Stacks:");
                var prev = new List<string>(); 
                foreach (var trace in stats[stat.ThreadId].Select(_ => _.StackTrace)) {
                    if (!prev.SequenceEqual(trace)) {
                        Console.WriteLine();
                        foreach (var method in trace) {
                            Console.WriteLine(method);
                        }
                    } else {
                        Console.WriteLine("<skipped>");
                    }
                    prev = trace;
                }
                Console.WriteLine("------------------------------------");

            }
        }

        private static int? GetPid(string pidOrProcessOrAppPool)
        {
            using (var serverManager = new ServerManager())
            {
                var appPool = serverManager.ApplicationPools.FirstOrDefault(
                    ap => ap.Name.Equals(pidOrProcessOrAppPool,
                    StringComparison.OrdinalIgnoreCase));
                if (appPool != null)
                {
                    if (appPool.WorkerProcesses.Count == 0)
                    {
                        Console.WriteLine("Error: no worker processes found for that app pool");
                        return null;
                    }
                    if (appPool.WorkerProcesses.Count > 1)
                    {
                        Console.WriteLine("Warning: multiple worker processes for that app pool, attaching to the first");
                    }
                    return appPool.WorkerProcesses[0].ProcessId;
                }
            }

            var processes = Process.GetProcessesByName(pidOrProcessOrAppPool);
            if (processes.Length < 1)
            {
                try
                {
                    return int.Parse(pidOrProcessOrAppPool);
                }
                catch
                {
                    Console.WriteLine("Error: could not find any processes with that name or pid");
                    return null;
                }
            }
            else
            {
                if (processes.Length > 1)
                {
                    Console.WriteLine("Warning: multiple processes share that name, attaching to the first");
                }
                return processes[0].Id;
            }
        }

        private static string FindAttachVersion(int pid)
        {
            var attachVersion = MdbgVersionPolicy.GetDefaultAttachVersion(pid);
            var installedVersions = new CLRMetaHost().EnumerateInstalledRuntimes().Select(r => r.GetVersionString()).ToList();
            if (installedVersions.Contains(attachVersion))
            {
                return attachVersion;
            }

            var matchingVersion = installedVersions.Find(v => attachVersion.Contains(v.Replace("v", "")) || v.Contains(attachVersion.Replace("v", "")));
            if (matchingVersion != null)
            {
                return matchingVersion;
            }

            Console.WriteLine("Error: could not find installed runtime attach version.");
            Console.WriteLine("  Default attach version: " + attachVersion);
            Console.WriteLine("  Installed versions: " + string.Join(", ", installedVersions));
            return null;
        }
    }
}
