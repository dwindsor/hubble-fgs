$stagingDir = "$PSScriptRoot\staging"

msiexec /qn /a $stagingDir\ebpf-for-windows.x64.1.0.0-rc1.msi TARGETDIR=$stagingDir\unpacked

Expand-Archive -Path $stagingDir\ntosebpfext-build-output.zip -DestinationPath $stagingDir\unpacked -Force
Expand-Archive -Path $stagingDir\unpacked\build-x64.Release.zip -DestinationPath $stagingDir\unpacked -Force

Expand-Archive -Path $stagingDir\tetragon-windows-build-output.zip -DestinationPath $stagingDir\unpacked -Force
Expand-Archive -Path $stagingDir\unpacked\Tetragon-Windows.zip -DestinationPath $stagingDir\unpacked\tetragon -Force

Expand-Archive -Path $stagingDir\shawl-v1.7.0-win64.zip -DestinationPath $stagingDir\unpacked\shawl -Force
