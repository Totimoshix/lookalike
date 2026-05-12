$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MinNodeMajor = 20

function Write-Step {
    param([string]$Message)
    Write-Host "[install] $Message"
}

function Fail-Step {
    param([string]$Message)
    throw "[install] ERROR: $Message"
}

function Refresh-Path {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machinePath;$userPath"
}

function Ensure-NodeInstalled {
    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
    $npmCommand = Get-Command npm -ErrorAction SilentlyContinue

    if ($nodeCommand -and $npmCommand) {
        return
    }

    $wingetCommand = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $wingetCommand) {
        Fail-Step "Node.js 20+ is required. Install Node.js LTS from https://nodejs.org/ and run this script again."
    }

    Write-Step "Node.js was not found. Installing Node.js LTS via winget."
    winget install OpenJS.NodeJS.LTS --accept-package-agreements --accept-source-agreements
    Refresh-Path
}

function Verify-NodeVersion {
    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
    $npmCommand = Get-Command npm -ErrorAction SilentlyContinue

    if (-not $nodeCommand -or -not $npmCommand) {
        Fail-Step "Node.js or npm is still not available after installation."
    }

    $nodeVersionText = & node -v
    $nodeMajor = [int]((& node -p "process.versions.node.split('.')[0]"))

    if ($nodeMajor -lt $MinNodeMajor) {
        Fail-Step "Node.js $MinNodeMajor+ is required. Found $nodeVersionText. Install a newer Node.js LTS release and run this script again."
    }

    $npmVersionText = & npm -v
    Write-Step "Using $nodeVersionText and npm $npmVersionText."
}

function Ensure-EnvFile {
    $envPath = Join-Path $RootDir ".env"
    $envExamplePath = Join-Path $RootDir ".env.example"

    if (Test-Path $envPath) {
        Write-Step ".env already exists. Leaving it unchanged."
        return
    }

    if (Test-Path $envExamplePath) {
        Copy-Item $envExamplePath $envPath
        Write-Step "Created .env from .env.example."
    }
    else {
        Write-Step "No .env.example file found. Skipping .env creation."
    }
}

Push-Location $RootDir

try {
    Write-Step "Checking prerequisites."
    Ensure-NodeInstalled
    Verify-NodeVersion
    Ensure-EnvFile

    Write-Step "Installing npm dependencies."
    npm install

    Write-Step "Building all workspaces."
    npm run build

    Write-Host ""
    Write-Host "[install] Installation complete."
    Write-Host "[install] Next steps:"
    Write-Host "[install] 1. Start the local API with: npm run start"
    Write-Host "[install] 2. Open chrome://extensions"
    Write-Host "[install] 3. Enable Developer mode"
    Write-Host "[install] 4. Load the unpacked extension from: extension/dist"
    Write-Host "[install] 5. If needed, edit .env to add optional provider keys before starting the API"
    Write-Host ""
}
finally {
    Pop-Location
}
