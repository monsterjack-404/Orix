param(
  [Parameter(Mandatory=$true)][ValidateSet('run','cleanup')][string]$Mode,
  [Parameter(Mandatory=$true)][string]$ConfigPath
)
$ErrorActionPreference = 'Stop'
try {
  $sourcePath = Join-Path $PSScriptRoot '..\native\windows-provider-launcher.cs'
  [Console]::Error.WriteLine('ORIX_CLEANUP:PS_START:' + $Mode)
  Add-Type -Path $sourcePath
  [Console]::Error.WriteLine('ORIX_CLEANUP:TYPE_LOADED')
  $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
  if ($Mode -eq 'cleanup') {
    [OrixWindowsSandbox.Launcher]::Cleanup([string]$config.sandboxRoot, [string]$config.profileName)
    exit 0
  }
  $environment = @{}
  if ($config.environment) {
    $config.environment.PSObject.Properties | ForEach-Object {
      $environment[$_.Name] = [string]$_.Value
    }
  }
  $exitCode = [OrixWindowsSandbox.Launcher]::Run(
    [string]$config.executable,
    [string[]]$config.args,
    [string]$config.cwd,
    [string]$config.sandboxRoot,
    [string]$config.profileName,
    $environment
  )
  exit [int]$exitCode
} catch {
  [Console]::Error.WriteLine('ORIX_WINDOWS_ISOLATION_ERROR=' + $_.Exception.Message)
  exit 125
}
