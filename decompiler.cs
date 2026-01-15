#:package System.CommandLine@2.0.2

using System.Diagnostics;
using System.CommandLine;
using System.CommandLine.Parsing;

var hytaleOnlyOption = new Option<bool>("--server-only")
{
    Description = "Only decompile server files at src\\com\\hypixel\\hytale",
};

RootCommand rootCommand = new("Decompiler");
rootCommand.Options.Add(hytaleOnlyOption);
rootCommand.Description = "Parallel Java .class decompiler using Vineflower";

ParseResult parseResult = rootCommand.Parse(args);

var src = Path.Combine(Environment.CurrentDirectory, "src");

if (parseResult.Errors.Count is 0 && parseResult.GetValue(hytaleOnlyOption) is bool hytaleOnly)
{
    if (hytaleOnly)
        src = Path.Combine(src, "com", "hypixel", "hytale");

    if (!Directory.Exists(src))
    {
        Console.WriteLine("The filtered folder does not exist: " + src);
        return;
    }
}

foreach (ParseError parseError in parseResult.Errors)
{
    Console.Error.WriteLine(parseError.Message);
}

await DecompileClassFilesParallelAsync(src);

return;

static async Task DecompileClassFilesParallelAsync(string srcFolder)
{
    Console.WriteLine("Starting Vineflower decompilation...");

    var vineflower = Path.Combine(Environment.CurrentDirectory, "vineflower-1.11.2.jar");

    var process = new Process();
    process.StartInfo.FileName = "java";
    process.StartInfo.Arguments = $"-jar \"{vineflower}\" \"{srcFolder}\" src";
    process.StartInfo.UseShellExecute = false;
    process.StartInfo.RedirectStandardOutput = true;
    process.StartInfo.RedirectStandardError = true;

    var stopwatch = Stopwatch.StartNew();

    process.OutputDataReceived += (_, e) =>
    {
        if (e.Data is not null)
            Console.WriteLine(e.Data);
    };

    process.ErrorDataReceived += (_, e) =>
    {
        if (e.Data is not null)
            Console.WriteLine(e.Data);
    };

    process.Start();
    process.BeginOutputReadLine();
    process.BeginErrorReadLine();

    await process.WaitForExitAsync();
    stopwatch.Stop();

    Console.WriteLine();
    Console.WriteLine($"Vineflower finished in {stopwatch.Elapsed:hh\\:mm\\:ss\\.fff}");
}