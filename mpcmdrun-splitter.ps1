function MPTest-File {
<#
.SYNOPSIS

Run MpCmdRun.exe on a given file.

Author: Karim Kanso
License: GPLv3
Required Dependencies: None

.DESCRIPTION

Run MpCmdRun.exe on a given file and return True/False or Exception depending on result.

.EXAMPLE

MPTest-File c:\some\file.exe

#>
    [CmdletBinding()]
    Param(
	# File to test
        [Parameter(Mandatory)]
	[string]$file
    )

    # probably never want to submit working files
    $mppref = Get-MpPreference
    if ($mppref.SubmitSamplesConsent -ne [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MpPreference.SubmitSamplesConsentType]::AlwaysPrompt -and $mppref.SubmitSamplesConsent -ne [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MpPreference.SubmitSamplesConsentType]::NeverSend) {
        throw "Sample submission enabled, not checking"
    }

    # probably a better way of doing this.
    $mpdir = (gci "C:\ProgramData\Microsoft\Windows Defender\Platform\" | Sort-Object LastWriteTime -Descending)[0].FullName
    $mpcmdrun = "$mpdir\MpCmdRun.exe"

    if (-Not (Test-Path $file -PathType Leaf)) {
        throw "Unable to access `"$file`"."
    }
    
    # Check file
    & $mpcmdrun -Scan -ScanType 3 -File $file -DisableRemediation *> $null
    switch ($LASTEXITCODE) {
        0 {$true}
	2 {$false}
        default { throw "Unexpected return code from MpCmdRun: $LASTEXITCODE" }
    }
}

function MPSearch-File {
<#
.SYNOPSIS

Search for a bad string in a file.

Author: Karim Kanso
License: GPLv3
Required Dependencies: None

.DESCRIPTION

Uses MPTest-File as an oracle to identify bad strings in a file via
binary search. The resulting file is saved into the working directory
with the extension `.bad`.

It is suggested to use a RamDrive for the working directory.

.EXAMPLE

$VerbosePreference = "Continue"
MPSearch-File c:\some\file.exe r:\

#>
    [CmdletBinding()]
    Param(
	# File to dissect.
        [ValidateScript(
             {
                 if(-Not ($_ | Test-Path -PathType Leaf) ){
                     throw "The File argument must be a file."
                 }
                 return $true
             })]
        [Parameter(Mandatory)]
	[IO.FileInfo]$File,

        # Working directory, ideally excluded from Windows Defender scans.
        [ValidateScript(
             {
                 if(-Not ($_ | Test-Path -PathType Container) ){
                     throw "The WorkingDir argument must be a directory."
                 }

                 # TODO: check against list contained at  (Get-MpPreference).ExclusionPath
                 
                 return $true
             })]
        [Parameter(Mandatory)]
        [IO.FileInfo]$WorkingDir,

        # Minimum size of window during binary search, size of 1 finds
        # the exact end of the bad string. Larger sizes are faster,
        # but less accurate.
        [ValidateScript({ $_ -gt 0 })]
        [int]$Threshold = 1
    )

    if (MPTest-File $File) {
        Write-Verbose "File passes MP check"
        return $true
    }
    
    $FileData = [IO.File]::ReadAllBytes($File)
    Write-Verbose "File Size: $($FileData.Length)"

    $WorkingFile = Join-Path $WorkingDir "z$($File.Name)"
    $BadFile = Join-Path $WorkingDir "$($File.Name).bad"
    Copy-Item $File $BadFile

    $WindowStart = 0
    $WindowEnd = $FileData.Length - 1

    while ($WindowEnd - $WindowStart -gt $Threshold) {
        $Midpoint = [int](($WindowEnd - $WindowStart) / 2) + $WindowStart
        Write-Verbose "Testing window: [$WindowStart-->$Midpoint<--$WindowEnd]"
        [IO.File]::WriteAllBytes($WorkingFile, $FileData[0..$Midpoint])
        if (MPTest-File $WorkingFile) {
            $WindowStart = $Midpoint
        } else {
            $WindowEnd = $Midpoint
            Move-Item $WorkingFile $BadFile -Force
        }
    }
    if (Test-Path $WorkingFile) {
        Remove-Item $WorkingFile -Force
    }
    
    $WindowEnd
}


function MPTest-FileWithPatch {
<#
.SYNOPSIS

Patch data into file before checking with MPTest-File

Author: Karim Kanso
License: GPLv3
Required Dependencies: None

.DESCRIPTION

Patch a file with a string (or byte array) and then run MpCmdRun.exe
on a given file and return True/False or Exception depending on
result.

Typical use-case of this is to inject known bad strings into a file
near the beginning, but after the file headers so that it drives out
more bad strings later on in the binary. This is because it appears
when the file is checked for bad strings, it is the presence of a
combination of the strings that trigger the flagging.

.EXAMPLE

MPTest-FileWithPatch c:\some\file.exe r:\ 250 -data "bad string to insert"

Insert UTF8 string at 250 byte offset and test. A temporary file is
created in R:\ and deleted afterwards.

.EXAMPLE

MPTest-FileWithPatch c:\some\file.exe r:\ 250 -data "string to insert" -encoding ([Text.Encoding]::Unicode) -Keep

Insert UTF16 string at 250 byte offset and test. A temporary file is
created in R:\ and not deleted afterwards. The will have extensions
`.test`.

#>
    [CmdletBinding()]
    Param(
	# File to test.
        [ValidateScript(
             {
                 if(-Not ($_ | Test-Path -PathType Leaf) ){
                     throw "The File argument must be a file."
                 }
                 return $true
             })]
        [Parameter(Mandatory)]
	[IO.FileInfo]$File,

        # Working directory, ideally excluded from Windows Defender scans.
        [ValidateScript(
             {
                 if(-Not ($_ | Test-Path -PathType Container) ){
                     throw "The WorkingDir argument must be a directory."
                 }
                 return $true
             })]
        [Parameter(Mandatory)]
        [IO.FileInfo]$WorkingDir,

        # Offset in file to write data, default 0
        [int]$Offset = 0,

        # data to patch with, accepted values are byte arrays and strings
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [object]$Data,

        # encoding to use for strings, default is utf8
        [Text.Encoding]$Encoding = [Text.Encoding]::UTF8,

        # set to not delete patched file after testing
        [switch]$KeepTestFile
    )

    BEGIN {
        $WorkingFile = Join-Path $WorkingDir "$($File.Name).test"
        if (Test-Path $WorkingFile) {
            throw "File already exists: $WorkingFile"
        }
        [IO.File]::Copy($File, $WorkingFile)
        $fs = [IO.File]::Open($WorkingFile, [IO.FileMode]::Open, [IO.FileAccess]::Write)
        $fs.Seek($Offset, [IO.SeekOrigin]::Begin) > $null
    }

    PROCESS {
        switch ($data) {
            {$_ -is [byte[]]} {
                $fs.Write($data, 0, $data.Length)
            }
            {$_ -is [string]} {
                $b = $Encoding.GetBytes($data)
                $fs.Write($b, 0, $b.Length)
            }
            default {
                throw "Unsupported type: $($data.GetType())"
            }
        }
    }

    END {
        $fs.Close()
        $result = MPTest-File $WorkingFile
        if (-not $KeepTestFile) {
            Remove-Item $WorkingFile
        }
        $result
    }
}
