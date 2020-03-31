# General Variables
$SCRIPT_NAME = $MyInvocation.MyCommand.Name;
if ((Get-Host).Version.Major -lt 3) {
    $SCRIPT_PATH = "$(Get-Location)\$SCRIPT_NAME"
} else {
    $SCRIPT_PATH = $MyInvocation.MyCommand.Source;
}
$SCRIPT_VERS = 'v.0.3';


function set_execution_policy {
    $policy = Get-ExecutionPolicy;
    if ($policy -ne 'bypass') {
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
    } else {Write-Host('[!] Execution Policy already bypass!')}
    if ((Get-ExecutionPolicy) -eq 'bypass') {
        Write-Host('[+] Execution Policy is now bypass!') -ForegroundColor Green;
    } else {
        Write-Host("[-] Unable to set Execution Policy... Remains $policy...") -ForegroundColor Red;
    }
}

function change_user($PS_V = $false) {
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
            if (!$PS_V) {$users = (Get-LocalUser).Name} else {$users = Get-WmiObject -Class Win32_userAccount | Select-Object 'Name'};
            Foreach ($user in $users) {
                if ($user -match $input_user ) {
                    if ($verbose) {Write-Host("[+] User $user Found") -ForegroundColor Green}
                    $u_count = 0;
                    break;
                } Elseif ($user -ne $input_user) {
                    $u_count++;
                }
                if ($users.Count -eq $u_count) {
                    $u_count = 0;
                    Write-Host("[!] User $input_user Not Found!") -ForegroundColor Red;
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
    if (Test-Path -Path 'C:\temp\') {$temp_path = 'C:\temp\'} elseif (Test-Path -Path $env:TEMP) {$temp_path = "$env:TEMP\"}
    Copy-Item -Path ".\PSPTK.ps1" -Destination $temp_path;
    Start-Process powershell -NoNewWindow -WorkingDirectory $temp_path -Credential $c;
}

function single_command_as_user($PS_V = $false) {
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
        if(!$PS_V) {
            $adm_grps = (Get-LocalGroup).Name  | Where-Object {$_ -match 'admin'};
            $is_admin = foreach ($group in $adm_grps) {
                if ((Get-LocalGroupMember -Group $group).Name -match $input_user) {$true} else {$false};
            }
        } else {
            $users = (Get-WmiObject Win32_group -filter "name='Administrators'").GetRelated() | Select-Object 'Name';
            $is_admin = foreach ($user in $users) {if ($user -match $input_user) {$true} else {$false}}
        }
        if ($is_admin -match 'True') {
            Write-Host("`n[!] User is Admin`n") -ForegroundColor Green;
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

# TODO Add scan for vulnerable processes
function check_processes {
    $processes = Get-Process;
    Write-Host("ID`tNAME") -ForegroundColor Cyan;
    foreach ($process in $processes) {
        Write-Host("$($process.Id)      `t$($process.Name)") -ForegroundColor Yellow;
    }
}

function check_services {
    $services = Get-Service;
    foreach ($service in $services) {
        if ($service.Status -match 'running') {
            Write-Host("$($service.Status)    `t$($service.Name)") -ForegroundColor Green;
        } else {
            Write-Host("$($service.Status)     `t$($service.Name)") -ForegroundColor Yellow;
        }
    }
}

function arch_os_info {
    $PS32 = $false;
    $OS32 = $false;
    $found_ver = '';
    $win_ver = @(('6.1', 'Windows 7 / Server 2008 R2'),
                 ('6.8', 'Windows 8 / Server 2012'),
                 ('6.3', 'Windows 8.1 / Server 2012 R2'),
                 ('10.0', 'Windows 10 / Server 2016'))

    if ([IntPtr]::size -eq 4) {$PS32 = $false} else {$PS32 = $true};
    if (${env:ProgramFiles(x86)}) {$OS32 = $false} else {$OS32 = $true};
    $cur_ver = ([string]([Environment]::OSVersion.Version).Major + '.' + [string]([Environment]::OSVersion.Version).Minor);
    foreach ($ver in $win_ver) {
        if ($ver[0] -match $cur_ver) {
            $found_ver = $ver[1];
        }
    }
    return $PS32, $OS32, $found_ver;
}

function menu {
    $BANNER = @"
     ____  ____  ____ _____ _  __
    |  _ \/ ___||  _ \_   _| |/ /
    | |_) \___ \| |_) || | | ' / 
    |  __/ ___) |  __/ | | | . \ 
    |_|   |____/|_|    |_| |_|\_\.ps1

__________________________________________________________

PowerShell Penetration Testing Toolkit
Path: $SCRIPT_PATH
Ver: $SCRIPT_VERS
__________________________________________________________

        - LOCAL INFORMATION -

USER INFORMATION:
    CURRENT USER...: $env:USERNAME
    COMPUTERNAME...: $env:COMPUTERNAME

SYSTEM INFORMATION:
    ARCHITECTURE...: $(if (!(arch_os_info)[1]) {'64bit'} else {'32bit'})
    OPERATING SYS..: $((arch_os_info)[2])
    PS ARCHITECTURE: $(if ((arch_os_info)[0]) {'64bit'} else {'32bit'})
    PS VERSION.....: $([string](Get-Host).Version.Major + '.' + [string](Get-Host).Version.Minor)
    HOMEPATH.......: $env:HOMEPATH
    USER TEMP PATH.: $(if ($env:TEMP) {$env:TEMP} else {"CAN'T FIND"})
    SYS TEMP PATH..: $(if (Test-Path "$env:HOMEDRIVE\temp") {'C:\temp'} else {"CAN'T FIND"})
    ONEDRIVE PATH..: $(if ($env:OneDrive -match 'onedrive') {$env:OneDrive} else {"CAN'T FIND"})
    LOCAL IP ADDR..: $(try{(Get-WmiObject Win32_NetworkAdapterConfiguration | `
                        Where-Object { (($null -ne $_.IPEnabled) -and ($null -ne $_.DefaultIPGateway)) } | `
                        Select-Object IPAddress -First 1).IPAddress[0]}catch{"CAN'T FIND"})

    1 - Set Execution Policy    |    2 - Change User
    3 - Arbitrary Code Execution
    4 - List All Processes      |    5 - List All Services
    q - Quit                    |    m - List this menu
__________________________________________________________

"@

    Write-Host($BANNER) -ForegroundColor Green;
    
}

function main {
    $menu_input = '';
    $PS_VER2 = $false
    if ((Get-Host).Version.Major -lt 3) {$PS_VER2 = $true}
    Clear-Host;
    menu;
    do {
        Write-Host("[$env:USERNAME] $ ") -NoNewline;
        $menu_input = $Host.UI.ReadLine();
        switch($menu_input) {
            '1' {set_execution_policy};
            '2' {change_user($PS_VER2)};
            '3' {single_command_as_user($PS_VER2)};
            '4' {check_processes};
            '5' {check_services};
            'm' {menu};
            'c' {Clear-Host}
        }
        if ($menu_input -ne '1' -and $menu_input -ne '2' `
        -and $menu_input -ne '3' -and $menu_input -ne '4' `
        -and $menu_input -ne '5' -and $menu_input -ne 'm' `
        -and $menu_input -ne 'c'  `
        -and $menu_input -ne ' ' -and $menu_input -ne '' `
        -and $menu_input -ne 'q' -and $menu_input -ne 'quit') {
            Write-Host("[+] Running $menu_input outside...");
            Invoke-Expression -Command $menu_input;
        }
    } while($menu_input -ne 'q' -and $menu_input -ne 'quit');
    if ($menu_input -eq 'q' -or $menu_input -eq 'quit') {Write-Host('Quitting...')};
}

main;
