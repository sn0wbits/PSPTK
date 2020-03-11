# General Variables
$SCRIPT_NAME = $MyInvocation.MyCommand.Name;
$SCRIPT_PATH = $MyInvocation.MyCommand.Source;
$SCRIPT_VERS = 'v.0.2';

function menu{
    $BANNER = @"
     ____  ____  ____ _____ _  __
    |  _ \/ ___||  _ \_   _| |/ /
    | |_) \___ \| |_) || | | ' / 
    |  __/ ___) |  __/ | | | . \ 
    |_|   |____/|_|    |_| |_|\_\.ps1
_________________________________________

PowerShell Penetration Testing Toolkit
Path: $SCRIPT_PATH
Ver: $SCRIPT_VERS
_________________________________________

        - LOCAL INFORMATION -

USER INFORMATION:
    CURRENT USER...: $env:USERNAME
    COMPUTERNAME...: $env:COMPUTERNAME

PATH INFORMATION:
    HOMEPATH.......: $env:HOMEPATH
    USER TEMP PATH.: $env:TEMP
    SYS TEMP PATH..: $(if (Test-Path "$env:HOMEDRIVE\temp") {'C:\temp'})
    ONEDRIVE PATH..: $(if ($env:OneDrive -match 'onedrive') {$env:OneDrive})

"@
Write-Host($BANNER);
}

menu;
function set_execution_policy {
    if (Get-ExecutionPolicy | ForEach-Object {$_ -ne 'bypass'}) {
        Write-Host("[!] Execution Policy is $policy not Bypass") -ForegroundColor Yellow;
        try {
            Set-ExecutionPolicy -ExecutionPolicy Bypass;
        } catch {
            Write-Host($Error[0]) -ForegroundColor Red;
            Write-Host('[!] Unable to set Execution Policy to Bypass!') -ForegroundColor Yellow;
            Write-Host('[!] Attempting to rerun script with bypass!') -ForegroundColor Yellow;
            try {
                Start-Sleep(2);
                powershell.exe -ep bypass -command "$SCRIPT_PATH";
            } catch {
                Write-Host($Error[0]) -ForegroundColor Red;
                Write-Host('[!] Unable to open script with bypass!') -ForegroundColor Yellow;
                Write-Host('[?] Contiune anyways? Y/N') -ForegroundColor Yellow;
                $usr_confirm = Read-Host('');
                if ($usr_confirm.ToLower() -ne 'y') {
                    Write-Host('[!] Exiting...') -ForegroundColor Yellow;
                    exit;
                } Else {
                    Write-Host('[!] Continuing...') -ForegroundColor Yellow;
                }
            }
        }
    }
}

function change_user {
    $input_user = '';
    $input_pass = '';
    $input_options = '';
    $c = '';
    $verbose = $false;
    $force = $false;
    $u_count = 0;

    Write-Host('[?] Please enter credentials to switch to...') -ForegroundColor Yellow;
    $input_user = Read-Host('[i] Username');
    $input_pass = Read-Host('[i] Password') ;
    $input_options = Read-Host("[i] Options:`nf = Force entered credentials.`nv = Verbose mode.`nEnter Options");
    if ($input_options -match 'f') {$force = $true};
    if ($input_options -match 'v') {$verbose = $true};

    if (!$force) {
        if ($verbose){Write-Host('[+] Enumerating Users...') -ForegroundColor Cyan};
        try {
            $users = Get-LocalUser;
            Foreach ($user in $users) {
                if ($user.Name -eq $input_user ) {
                    if ($verbose){Write-Host('[+] User ' + $user.Name + ' Found') -ForegroundColor Green}
                    $u_count = 0;
                    break;
                } Elseif ($user.Name -ne $input_user) {
                    $u_count++;
                }
                if ($users.Count -eq $u_count) {
                    $u_count = 0;
                    Write-Host('[!] User ' + $input_user + ' Not Found!') -ForegroundColor Red;
                    throw ' ';
                }
            }
        } catch {
            Write-Host($Error[0]) -ForegroundColor Red;
            Write-Host('[!] Unable to Enumerate Users...') -ForegroundColor Red;
            Write-Host('[?] If you know the user exists retry using -f or --force') -ForegroundColor Yellow;
            exit;
        }
    } Else {
        $user = $input_user;
    }

    $e = "$env:COMPUTERNAME\$input_user";
    $p = ConvertTo-SecureString $input_pass -AsPlainText -Force;
    $c = New-Object System.Management.Automation.PSCredential($e, $p);

    if ($verbose) {
        $un = $c.GetNetworkCredential().UserName;
        $pw = $c.GetNetworkCredential().Password;
        Write-Host("
    ---------------------------
    $e
    ---------------------------
    USER:
        $un

    PASS:
        $pw");
    }
    Copy-Item -Path ".\PSPTK.ps1" -Destination "C:\temp\PSPTK.ps1";
    Start-Process powershell -NoNewWindow -WorkingDirectory "$env:HOMEDRIVE\temp" -Credential $c;
}

function single_command_as_user {
    $input_user = '';
    $input_pass = '';
    $input_command = '';
    $input_verb = '';
    $input_perm = '';
    $verbose = $false;
    $check_perm = $false;

    Write-Host('[?] Please enter credentials to use...') -ForegroundColor Yellow;
    $input_user = Read-Host('[i] Username');
    $input_pass = Read-Host('[i] Password');
    $input_verb = Read-Host('[i] Verbose? Y/n');
    $input_perm = Read-Host('[i] Check for permissions? Y/n');
    if ($input_verb.ToLower() -match 'y') {$verbose = $true};
    if ($input_Perm.ToLower() -match 'y') {$check_perm = $true}
    if ($verbose) {Write-Host('[+] Generating credentials...') -ForegroundColor Cyan};
    
    $e = "$env:COMPUTERNAME\$input_user";
    $p = ConvertTo-SecureString $input_pass -AsPlainText -Force;
    $c = New-Object System.Management.Automation.PSCredential($e, $p);

    if ($check_perm) {
        $adm_grps = (Get-LocalGroup).Name  | Where-Object {$_ -match 'admin'};
        $is_admin = foreach ($group in $adm_grps) {
            if ((Get-LocalGroupMember -Group $group).Name -match $input_user) {$true} else {$false};
        }
        if ($is_admin -match 'True') {
            Write-Host("`n[!] User is Admin`n") -ForegroundColor Green;
            break;
        } else {
            Write-Host("`n[!] User is not Admin`n") -ForegroundColor Red;
        }
    }

    $input_command = Read-Host('[i] Command');
    $input_command = [ScriptBlock]::Create($input_command);
    if ($verbose) {Write-Host("[+] Attempting to run command $input_command as user $input_user") -ForegroundColor Cyan};
    Write-Host("$env:USERNAME -> $input_user > $input_command") -ForegroundColor Magenta;
    try {
        if ($verbose) {Write-Host("[+] Starting job")};
        $job = Start-Job -Credential $c -ScriptBlock $input_command;
        if ($verbose) {Write-Host("[+] Waiting for job...") -ForegroundColor Cyan};
        Wait-Job $job | Out-Null;
        if ($verbose) {Write-Host("[+] Receiving job...") -ForegroundColor Cyan};
        $job_result = Receive-Job $job;
    } Catch {
        Write-Host($Error[0]) -ForegroundColor Red;
    }
    Write-Host("$env:USERNAME <- $input_user > $job_result");
}