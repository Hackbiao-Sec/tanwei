# Build the Tanwei Console app icon: build/icon.png (512 preview) + build/icon.ico (16/24/32/48/64/128/256).
# The drawing code lives in scripts/icon/TanweiIcon.cs (GDI+, kept out of the here-string to avoid line loss).
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root 'build'
$cs = Join-Path $PSScriptRoot 'icon\TanweiIcon.cs'
New-Item -ItemType Directory -Force -Path $build | Out-Null

Add-Type -TypeDefinition (Get-Content -Raw -Path $cs) -ReferencedAssemblies System.Drawing -Language CSharp
Write-Output ([TanweiIcon]::Run($build))
