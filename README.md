
# STIG-WN11-AU-000583-# WN11-AU-000583

Windows 11 must be configured to audit handle manipulation failures.

```powershell
<#
.SYNOPSIS
    This PowerShell script ensures that Windows 11 audits Object Access - Handle Manipulation failures (Advanced Audit Policy: Failure enabled).

.NOTES
    Author          : Sean Keener
    LinkedIn        : https://www.linkedin.com/in/sean-k-308049210/
    GitHub          : github.com/seankeener
    Date Created    : 2026-11-15
    Last Modified   : 2026-11-15
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000583
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AU-000583/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run from an elevated PowerShell prompt. The script applies the fix automatically and the window stays open when it finishes.
    Only the Failure setting is changed. An existing Success setting for this subcategory is left as it is.
    Example syntax:
    PS C:\> .\WN11-AU-000583.ps1
    Result codes: 0 = compliant, 2 = error (stored in $LASTEXITCODE)
#>

[CmdletBinding()]
param()

$StigId          = 'WN11-AU-000583'
$SubcategoryName = 'Handle Manipulation'
$SubcategoryGuid = '{0CCE9223-69AE-11D9-BED3-505054503030}'

# Returns the Inclusion Setting text from auditpol (for example: 'No Auditing', 'Success', 'Failure', 'Success and Failure')
function Get-AuditSetting {
    $raw   = & auditpol.exe /get "/subcategory:$SubcategoryGuid" /r 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol /get failed: $($raw -join ' ')" }
    $lines = @($raw | Where-Object { $_ -match ',' })
    if ($lines.Count -lt 2) { throw "Unexpected auditpol output: $($raw -join ' ')" }
    $fields = $lines[-1] -split ','
    return $fields[4].Trim()
}

function Invoke-StigFix {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[$StigId] ERROR - This script must be run as Administrator." -ForegroundColor Red
        return 2
    }

    try {
        $current = Get-AuditSetting

        if ($current -match 'Failure') {
            Write-Host "[$StigId] ALREADY COMPLIANT - '$SubcategoryName' is set to '$current' (required: Failure)" -ForegroundColor Green
            return 0
        }

        Write-Host "[$StigId] NON-COMPLIANT - '$SubcategoryName' is set to '$current' (required: Failure). Applying fix..." -ForegroundColor Yellow

        & auditpol.exe /set "/subcategory:$SubcategoryGuid" /failure:enable 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[$StigId] ERROR - auditpol /set failed (exit code $LASTEXITCODE)." -ForegroundColor Red
            return 2
        }

        $after = Get-AuditSetting
        if ($after -match 'Failure') {
            Write-Host "[$StigId] REMEDIATED - '$SubcategoryName' is now set to '$after'" -ForegroundColor Green
            return 0
        }

        Write-Host "[$StigId] ERROR - Setting did not persist after applying the fix (currently '$after')." -ForegroundColor Red
        return 2
    }
    catch {
        Write-Host "[$StigId] ERROR - $($_.Exception.Message)" -ForegroundColor Red
        return 2
    }
}

$result = 2
try {
    $result = Invoke-StigFix
}
finally {
    $global:LASTEXITCODE = $result
    Write-Host ""
    Read-Host "Press Enter to close this window" | Out-Null
}
```
