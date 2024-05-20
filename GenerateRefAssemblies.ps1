$refasmer = "refasmer.exe"
$command = Get-Command $refasmer -ErrorAction SilentlyContinue

if ($command -eq $null) {
    Write-Host "Refasmer not found. Install it as global .NET tool."
    Write-Host "dotnet tool install -g JetBrains.Refasmer.CliTool"
    dotnet tool install -g JetBrains.Refasmer.CliTool
}

if (Test-Path ".\ref") {
    Remove-Item ".\ref" -Recurse -Force 
}

$platforms = @("x64", "ARM64")
$configurations = @("Debug", "DebugSigning", "Release", "ReleaseSigning")
$targetFrameworks = @("net6.0", "net462")
$targetAssemblyName = "Microsoft.O365.Security.Native.ETW.dll"

$generated = @()
$platforms | ForEach-Object {
    $platform = $_
    $configurations | ForEach-Object {
        $configuration = $_
        $targetFrameworks | ForEach-Object {
            $targetFramework = $_
            $targetAssembly = ".\krabs\$platform\$configuration\$targetFramework\$targetAssemblyName"
            if (($generated -notcontains $targetFramework) -and (Test-Path $targetAssembly)) {
                Write-Host "Generating reference assembly for $targetAssembly"
                & $refasmer -v -O "ref\$targetFramework" -c $targetAssembly
                if (Test-Path ".\ref\$targetFramework\$targetAssemblyName") {
                    Write-Host "Reference assembly for $targetFramework generated successfully."
                    $generated += $targetFramework
                }
                else {
                    Write-Host "Failed to generate reference assembly."
                }
            }
        }
    }
}