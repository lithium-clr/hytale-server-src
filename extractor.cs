using System;
using System.IO.Compression;

Console.WriteLine("Starting extraction...");

const string HytaleDir = @"Hytale\install\release\package\game\latest\Server\";
const string ZipFileName = "HytaleServer.jar";

var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
var sourcePath = Path.Combine(appData, HytaleDir, ZipFileName);

try
{
    if (!File.Exists(sourcePath))
    {
        Console.WriteLine("The source file does not exist: " + sourcePath);
        return;
    }

    var destinationPath = Path.Combine(Environment.CurrentDirectory, "src");

    if (Directory.Exists(destinationPath))
        Directory.Delete(destinationPath, true);

    await ExtractZipFastAsync(sourcePath, destinationPath);
    Console.WriteLine($"\nFiles extracted to {destinationPath}");
}
catch (Exception ex)
{
    Console.WriteLine("Error: " + ex.Message);
}

static async Task ExtractZipFastAsync(string zipPath, string extractPath)
{
    using var zipStream = new FileStream(zipPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
    using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

    var entries = archive.Entries.Where(e => !string.IsNullOrEmpty(e.Name)).ToList();
    var total = entries.Count;
    var completed = 0;
    var running = true;

    var progressTask = Task.Run(async () =>
    {
        while (running)
        {
            var done = Volatile.Read(ref completed);
            Console.Write($"\rExtracting: {done}/{total} ({done * 100 / total}%)");
            await Task.Delay(1000);
        }
    });

    foreach (var entry in entries)
    {
        var destinationPath = Path.Combine(extractPath, entry.FullName);
        var directoryPath = Path.GetDirectoryName(destinationPath);

        if (!string.IsNullOrEmpty(directoryPath))
        {
            if (File.Exists(directoryPath))
                File.Delete(directoryPath);

            Directory.CreateDirectory(directoryPath);
        }

        if (Directory.Exists(destinationPath))
            Directory.Delete(destinationPath, true);

        using var entryStream = entry.Open();
        using var fileStream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);

        await entryStream.CopyToAsync(fileStream);
        Interlocked.Increment(ref completed);
    }

    running = false;
    await progressTask;

    Console.WriteLine($"\rExtracting: {total}/{total} (100%)");
}
