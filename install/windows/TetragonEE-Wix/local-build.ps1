$productCode = "65ECCB36-3AF8-4992-B9E7-A20B31D4FBFB"

# Run the build
dotnet build $PSScriptRoot\TetragonEnterprise.sln `
    /p:StagingRoot=$PSScriptRoot\staging `
    /p:ProductCode=$productCode `
    /p:Platform=x64 `
    -v 9

# Check if build succeeded
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}