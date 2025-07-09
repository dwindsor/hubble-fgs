function Get-TokenStatistics {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class TokenInfo {
    public enum TOKEN_INFORMATION_CLASS {
        TokenUser = 1,
        TokenStatistics = 10
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_STATISTICS {
        public LUID TokenId;
        public LUID AuthenticationId;
        // ... other fields omitted for brevity
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        IntPtr TokenInformation,
        int TokenInformationLength,
        out int ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

    $TOKEN_QUERY = 0x0008
    $tokenHandle = [IntPtr]::Zero
    $processHandle = [TokenInfo]::GetCurrentProcess()
    if (-not [TokenInfo]::OpenProcessToken($processHandle, $TOKEN_QUERY, [ref]$tokenHandle)) {
        Write-Error "OpenProcessToken failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        return
    }

    $size = 0
    [TokenInfo]::GetTokenInformation($tokenHandle, [TokenInfo+TOKEN_INFORMATION_CLASS]::TokenStatistics, [IntPtr]::Zero, 0, [ref]$size) | Out-Null
    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    if (-not [TokenInfo]::GetTokenInformation($tokenHandle, [TokenInfo+TOKEN_INFORMATION_CLASS]::TokenStatistics, $ptr, $size, [ref]$size)) {
        Write-Error "GetTokenInformation failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        [TokenInfo]::CloseHandle($tokenHandle) | Out-Null
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
        return
    }

    $stats = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [Type][TokenInfo+TOKEN_STATISTICS])
    $authId = ([uint64]$stats.AuthenticationId.HighPart -shl 32) -bor $stats.AuthenticationId.LowPart
    $tokenId = ([uint64]$stats.TokenId.HighPart -shl 32) -bor $stats.TokenId.LowPart

    [TokenInfo]::CloseHandle($tokenHandle) | Out-Null
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)

    return $authId
}
