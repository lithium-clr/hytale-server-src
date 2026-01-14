# Hytale Server Decompiled Source

This repository contains the decompiled source code of the Hytale server.

## Prerequisites

Before you begin, ensure you have the following installed on your system:

*   [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (or later)
*   [Java Runtime Environment (JRE)](https://www.java.com/download/) (version 21 recommended)

## Instructions

Follow these steps to extract and decompile the server source code.

### 1. Extract Server Files

The first step is to extract the server `.class` files from your Hytale installation.

The `extractor.cs` script automates this process. It locates the `HytaleServer.jar` file in the default installation directory (`%APPDATA%\Hytale\install\release\package\game\latest\Server\`) and extracts its contents into the `src` directory.

To run the extractor, execute the following command in your terminal:

```sh
dotnet run extractor.cs
```

### 2. Decompile Source Code

Once the files are extracted, you can decompile them into Java source code using the `decompiler.cs` script. This script uses [Vineflower](https://github.com/Vineflower/vineflower) to decompile the `.class` files from the `src` directory into the `decompiled_src` directory.

To run the decompiler, use the following command:

```sh
dotnet run decompiler.cs
```

This will decompile all the extracted files.

#### Partial Decompilation

If you only want to decompile the main server files (located at `src/com/hypixel/hytale`), you can use the `--server-only` flag:

```sh
dotnet run decompiler.cs --server-only
```

This will be faster than a full decompilation.