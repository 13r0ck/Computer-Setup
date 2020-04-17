#Requires -RunAsAdministrator
#Version DEV 1.2.3

# Required Variables
$Global:LogLocation = "$ENV:USERPROFILE\Desktop\Log"
$press_enter_in = @("dcu-cli","cmd")
$trusted_psremoting_hosts = @("Not-Matts")

########## - Functions - ##########

### Update Functions ###
function Install-ScriptWindowsUpdate {
        [CmdletBinding()]
        Param()
        if (-not(Get-Module PSWindowsUpdate -ListAvailable))
            {   
                Write-Verbose "Installing Powershell module PSWindowsUpdate"
                Install-PackageProvider -Name "Nuget" -RequiredVersion "2.8.5.208" -Scope CurrentUser -Force
                Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
                Install-Module -Name PSWindowsUpdate -RequiredVersion "2.1.1.2" -Scope CurrentUser -Confirm:$false -Force
                #Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
                Write-Verbose "$?"
                Write-Verbose "$($Error[-1])"
            }
    try 
    {
        $script_windowsupdates = $null
        $script_windowsupdates = (Install-WindowsUpdate -AcceptAll -IgnoreReboot -confirm:$false)
    }
    catch
    {
        if (Get-module PSWindowsUpdate -ListAvailable)
        {
            return "Module Install Success, Update Failure" #unknown error. Report failure.
        }
        else
        {
            return "Module Install Failure"
        }
    }
    #success
    if (($script_windowsupdates.Name -eq "nuget") -or ("" -eq $script_windowsupdates.objects) -or ($null -eq $script_windowsupdates) -or ($script_windowsupdates.count -eq 0)) {return 0} #standarddize that 0 means success
    
    #failure
    $windows_updates_failed = 0
    foreach ($update in $script_windowsupdates)
    {
        if ($update.Result -eq "Failed") {$windows_updates_failed++}
    }
    if ($windows_updates_failed -eq $script_windowsupdates.count)
    {
        return 1
    }
    
    #in progress
    return $script_windowsupdates #Returns 0 if successful, otherwise all installed updates are returned.
}

function Install-ScriptLenovoUpdate {
    [CmdletBinding()]
    Param()
    if (-not(Get-Module LSUClient -ListAvailable))
        {   
            Write-Verbose "Installing Powershell module LSUCLient"
            #Update_Log @("OEM_Updates","Status","In Progress") "Lenovo have begun installing. If this message is seen at the finish of the script, then Lenovo Updates have failed. Please install manually."
            Install-PackageProvider -Name "Nuget" -RequiredVersion "2.8.5.208" -Force
            #Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
            Install-Module -Name LSUClient -RequiredVersion "1.1.0" -Scope CurrentUser -Confirm:$false -Force
        }
try 
{
    $lenovo_update = Get-LSUpdate
    $lenovo_update | Install-LSUpdate
    
}
catch
{
    if (Get-module LSUClient)
    {
        return "Module Install Success, Update Failure" #unknown error. Report failure.
    }
    else
    {
        return "Module Install Failure"
    }
}
if ($null -eq $lenovo_update)
{
    return 0 # All updates are installed.
}
else
{
    return 1 # A reboot is required.
}
}

function Update-DellDrivers {
    #This function relies on DCU-CLI. This is installed with Dell Command Update. For the help run the code [&"<path>\dcu-cli.exe" /help] to get the version number and all possible switches
    #Link for documentation install: https://www.dell.com/support/manuals/us/en/04/command-update-v3.1/dellcommandupdate_3.1_ug/dell-command--update-command-line-interface?guid=guid-c8d5aee8-5523-4d55-a421-1781d3da6f08&lang=en-us
    
    #DCU-CLI has MANY other options that are not supported by this script. See dell documentation for more info. That will likely be userfull if wanting to roll dell updates out outside of this script
    #Options include, silent, bios passwords, automatic scheduling, blah blah

    #This does not currently support restricting specific dell udpates.
    if ((get-ciminstance -ClassName Win32_ComputerSystem).Manufacturer -ne "Dell Inc.") {
        return 3 #Reutrn that it is not a dell. Same return code as dcu-cli
    }

    $LASTEXITCODE = $null
    if (-not(IsInstalled "Dell Command")) {
        $dell_command_installer = Get-Item "$ENV:USERPROFILE\Desktop\amnet_computer_setup\Installers\*dell*"
        if (-not(Install-Software "Dell Command" $dell_command_installer.FullName "Windows Installer*Product Name: Dell Command | Update*success or error status: 0." 60 "/s")) {
            return "Failed to install"
        }
        Start-Sleep -s 3
        if (-not(Test-Path "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe")) # Verify that DCU-CLi installed. If it is not found, then report error.
            {
                return "DCU-CLI application missing"
            }
        $dcu_cli = Start-Process -FilePath "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/driverInstall" -Wait -PassThru
        return $dcu_cli.ExitCode
    }
    $dcu_cli = Start-Process -FilePath "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/applyUpdates" -Wait -PassThru
    return $dcu_cli.ExitCode
}

### GUI functions ###
function Get_UserPass($formTitle, $textTitle, $background_color="white", $text_color="black"){
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
    Write-Host "Get_UserPass has been started"
    $fun_colors = @("#ff5050","#ffffff","#3399ff")
    if ($background_color -ne "white") {$text_color = "white";$fun_colors = @("#ffffff", "#ffffff". "#ffffff")}

    $objForm = New-Object System.Windows.Forms.Form
    #$objForm.Text = $formTitle
    $objForm.Size = New-Object System.Drawing.Size(300,230)
    $objForm.BackColor = $fun_colors[(Get-Random -Minimum 0 -Maximum 2)]
    $objForm.StartPosition = "CenterScreen"
    $objForm.ControlBox = $false
    $objForm.ShowInTaskbar = $false
    $objForm.FormBorderStyle = "None"


    $objForm.KeyPreview = $True
    $objForm.Add_KeyDown({if ($_.KeyCode -eq "Enter") {$Script:userInput=@($objUserBox,$objTextBox).Text;$objForm.Close()}})
    $objForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") {$objForm.Close()}})

    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Size(110,170)
    $OKButton.Size = New-Object System.Drawing.Size(75,23)
    $OKButton.Text = "Enter"
    $OKButton.Add_Click({$Script:userInput=@($objUserBox,$objTextBox).Text;$objForm.Close()})
    $objForm.Controls.Add($OKButton)
    
    #Info
    $objLabel = New-Object System.Windows.Forms.Label
    $objLabel.Location = New-Object System.Drawing.Size(30,20)
    $objLabel.Size = New-Object System.Drawing.Size(280,30)
    $objLabel.Text = $textTitle
    if ($background_color -ne "white") {$objLabel.ForeColor = "$background_color"}
    $objForm.Controls.Add($objLabel)

    #Username text
    $objLabel = New-Object System.Windows.Forms.Label
    $objLabel.Location = New-Object System.Drawing.Size(15,63)
    $objLabel.Size = New-Object System.Drawing.Size(75,30)
    $objLabel.Text = "User name: "
    $objForm.Controls.Add($objLabel)

    #Password text
    $objLabel = New-Object System.Windows.Forms.Label
    $objLabel.Location = New-Object System.Drawing.Size(15,114)
    $objLabel.Size = New-Object System.Drawing.Size(75,30)
    $objLabel.Text = "Password: "
    $objForm.Controls.Add($objLabel)

    #UserName
    $objUserBox = New-Object System.Windows.Forms.TextBox
    $objUserBox.Location = New-Object System.Drawing.Size(105,60)
    $objUserBox.Size = New-Object System.Drawing.Size(160,20)
    $objUserBox.Text = "amnet_admin"
    $objUserBox.ForeColor = $text_color
    $objUserBox.BackColor = $background_color
    $objForm.Controls.Add($objUserBox)

    #Password
    $objTextBox = New-Object System.Windows.Forms.TextBox
    $objTextBox.Location = New-Object System.Drawing.Size(105,110)
    $objTextBox.Size = New-Object System.Drawing.Size(160,20)
    $objTextBox.ForeColor = $text_color
    $objTextBox.BackColor = $background_color
    $objTextBox.UseSystemPasswordChar = $true
    $objForm.Controls.Add($objTextBox)

    $objForm.Topmost = $True

    $objForm.Add_Shown({$objForm.Activate();$objTextBox.focus()})

    [void] $objForm.ShowDialog()

    return $userInput
}

### General functions ###

function IsInstalled {
    Param([string]$program_name)
    @(Get-WmiObject -Class Win32_Product) | ForEach-Object {if ($_.Name -like "*$program_name*") {return $true}}
}

Function Restart-ComputerAndWait {
    #Fixes the issue of the script continuing with other commands after Restart-Computer cmdlet is issued. For some reason the -wait switch is only for ps remoting, not the local machine
    Restart-Computer -Force
    Start-Sleep -s 600
}

function parse_for_environment_variables
    {
        Param([string]$string)
        $env_variables = [Environment]::GetEnvironmentVariables()
        foreach ($env_variable in $env_variables.Keys) {
            $env_variable_orig = $env_variable
            $env_variable = $env_variable.ToUpper()
            #$string = $string.Replace('$ENV:' + "$env_Variable", $env_variables."$env_variable_lower")
            $string = $string.Replace('$ENV:' + "$env_Variable", $env_variables."$env_variable_orig")
        }
        return $string
    }

function Update_Log([System.Array]$category,[string]$result) { #The fist item of the array must always be the one of the direct child nodes of #document.Log
    [xml]$success_log = Get-Content "$Global:LogLocation\Success Log.xml"
    #$category[0] Top level.
    #$category[1] Sub level , etc
    $node = $success_log.Log.SelectSingleNode($category[0])
        switch ($category[1]) {
            "Status"    {
                            $node.Status.set_InnerText($result)
                            $node.Status.script_status = $category[2]
                            if ($category[3] -eq "+1")
                            {
                                $node.Status.reboot_number = "$([int]$node.Status.reboot_number + 1)"
                            }
                        }
            "Results"   { #Creat a new new element with the result
                            $results_node = $node.SelectSingleNode("Results")
                            $new_element = $success_log.CreateElement("Result")
                            $new_element.set_InnerText($result)
                            $results_node.AppendChild($new_element) | Out-Null
                        }
        }
    try {
        try {
            $success_log.Save("$Global:LogLocation\Success Log.xml") | Out-Null
        } catch {
            Start-Sleep -s 0.3
            $success_log.Save("$Global:LogLocation\Success Log.xml") | Out-Null
        }
    } catch {
        Throw "Unable to save to the Success Log. Script is unable to continue. Please try running the script again, if that also fails, then contact the script developer."
    }
    return $success_log
}

#function Get-WindowsEdition
#{
#    return $editions[(get-ciminstance -ClassName Win32_OperatingSystem).OperatingSystemSKU])
#}

function Write_AsColor ([int]$foreground_color) #Write change the foreground color of
    { #returns the color that it was before
        # 1  -> Dark Blue
        # 2  -> Dark Green
        # 3  -> Dark Cyan
        # 4  -> Dark Red
        # 5  -> Dark Magenta
        # 6  -> Dark Yellow
        # 7  -> Gray
        # 8  -> Dark Gray
        # 9  -> Blue
        # 10 -> Green
        # 11 -> Cyan
        # 12 -> Red
        # 13 -> Magenta
        # 14 -> Yellow
        # 15 -> White
        $previous_foreground_color = $host.ui.RawUI.ForegroundColor.value__
        if ($null -ne $foreground_color) {
            $host.ui.RawUI.ForegroundColor = "$foreground_color"
        }
    return @($previous_foreground_color,$previous_background_color)
    }


### Software install functions ###
function loading_animation {
    Param([System.Management.Automation.Job]$job, [System.Array]$loading_animation, [string]$end_message)
    $i = 0
    while($job.JobStateInfo.State -eq "Running") {
        Write-Host -NoNewLine $loading_animation[$i % 4 ]"`r"
        Start-Sleep -Milliseconds 125
        $i++
    }
    for ($k = 0; $k -le $loading_animation[($i-1) % 4].length; $k++) {Write-Host -NoNewLine " "}
    Write-Host "`r$end_message"
}
function Install-Software
    { #Installes given software and checks for windows event for sucessful install. If event is found, returns true. Else false after timeout
        [CmdletBinding()]
        Param([string]$program_name, [string]$install_location, [string]$wait_for_event, [int]$wait_each_attempt, [string]$install_switch=$null)
        $is_installed = $false
        for ($i=1;$i -lt 4;$i++)
            {
                $install_location = Resolve-Path (parse_for_environment_variables "$install_location")
                $install_switch = parse_for_environment_variables "$install_switch"

                #Test for the existance of an installer at the given location.
                if (Test-Path $install_location)
                    {
                        Write-Verbose "Installing: $install_location $install_switch"
                        if ("" -ne $install_switch) {Start-Process "$install_location" "$install_switch"}
                        else {Start-Process "$install_location"}
                        $is_installed = wait_for_installed_event "$wait_for_event" "information" $wait_each_attempt
                        if ($is_installed -eq "Installed")
                            {
                                Write-Verbose "Installed Successfully"
                                return "Installed Successfully"
                            }
                    }
                else
                    {
                        Write-Verbose "Path not found"
                        return "Path Not Found"
                    }
            }
        Write-Verbose "Install either failed, or was never detected."
        return $false
    }

function wait_for_installed_event
    {
        Param([string]$Message, [string]$Entry_Type, [int]$Wait_Time)
        $start_time = Get-Date
        $change_in_seconds = 0
        While ($change_in_seconds -le $Wait_Time) {

            # This is because the get-event log can sometimes return the error "Access is denied" I have only ever seen this once. The solution was to simply run again.
            try
            {$event_log = (Get-EventLog "application" -EntryType $Entry_Type -Message $Message -Newest 1 -After $start_time).Message}
            catch
            {$event_log = (Get-EventLog "application" -EntryType $Entry_Type -Message $Message -Newest 1 -After $start_time).Message}
        
            if ($event_log){ #returned log met the given criteria, thus not null
                Write-Verbose $event_log
                return "Installed" #Ladies and Gentlemen, We Got Him!
            }
            Start-sleep -Seconds 0.5
            $current_time = Get-Date
            $change_in_seconds = ($current_time - $start_time).totalseconds
        }
        return "Install Failed" #After given number of seconds the event was never found.
    }

### Domain / VPN ###

function ConnectTo_VPN {
    param ([bool]$Create, [string]$username, [string]$password)
    [xml]$smart = Get-Content "$ENV:USERPROFILE\Desktop\amnet_computer_setup\Config\smart.xml"
    #Create all the useful variables
    $server_address = $smart.xml.client_config.vpn.server_address
    $connection_name = $smart.xml.client_config.vpn.connection_name
    $preshared_key = $smart.xml.client_config.vpn.preshared_key
    $encryption_level = $smart.xml.client_config.vpn.encryption_level
    $tunnel_type = $smart.xml.client_config.vpn.tunnel_type
    $authentcation_method = $smart.xml.client_config.vpn.authentication_method
    $remember_credential = $smart.xml.client_config.vpn.remember_credential 

    if ($remember_credential.ToUpper() -eq "TRUE") {$remember_credential = $true}
    else {$remember_credential = $false}

    try
    {
        if ($create -eq $true)
        {
            if ($tunnel_type.ToUpper() -eq "L2TP")
            {
                Add-VpnConnection -Name $connection_name -ServerAddress $server_address -TunnelType $tunnel_type -EncryptionLevel $encryption_level -RememberCredential $remember_credential -L2tpPsk $preshared_key -AuthenticationMethod $authentcation_method -AllUserConnection $true -Force -ErrorAction Stop
                #Start-Sleep -s 2
                #Set-VpnConnection -RememberCredential $remember_credential -EncryptionLevel $encryption_level -Name $connection_name
            }
            elseif ($tunnel_type.ToUpper() -eq "PPTP")
            {
                Add-VpnConnection -Name $connection_name -ServerAddress $server_address -TunnelType $tunnel_type -EncryptionLevel $encryption_level -RememberCredential $remember_credential -AuthenticationMethod $authentcation_method -Force -ErrorAction Stop
            }
            else
            {
                Add-VpnConnection -Name $connection_name -ServerAddress $server_address -AllUserConnection $true -TunnelType $tunnel_type -EncryptionLevel $encryption_level  -RememberCredential $remember_credential -AuthenticationMethod $authentcation_method -Force -ErrorAction Stop
                #Start-Sleep -s 2
                #Set-VpnConnection -RememberCredential $remember_credential -EncryptionLevel $encryption_level -Name $connection_name
            }
            if ($?)
            {
                Update_Log @("VPN","Status","In Progress") "Creating the VPN was successful. Not yet connected"
            }
            else
            {
                Write-Host "VPN Creation error:`n`n$_" -ForegroundColor Red
                Throw "VPN Error" #Jump to the catch to log the VPN connection failed.
            }
        }
    }
    catch
    {
        Write-Host "VPN Creation error:`n`n$_" -ForegroundColor Red
        $return_script = $_
    }

    # Tries to connect to vpn 3 times with a 1 min break between each attempt
    for($i=1; $i -le 3; $i++)  {   
        $output = [string](rasdial.exe $connection_name $username $password)
        if ($output.Contains("user name and password combination you provided is not recognized"))
        {
            return "Username_or_Password_Failure"  #Return that the credentials are incorrect.
        }
        
        #This try/catch is a work arround because Get-VpnConnection does not get all VPNs, it breaks VPN's into alluserconnection and not.
        
        $vpns = Get-VpnConnection -Name $connection_name
        if ($null -eq $vpns) # If the vpn was configured to be connectable by all users.
        {
            $vpns = Get-VpnConnection -Name $connection_name -AllUserConnection
        }
        if ($vpns.Length -gt 1)
        {
            $vpns = $vpns | Where-Object {$_.Name -like "*$connection_name*"}
        }

        if ($vpns.ConnectionStatus -eq "Connected")
        {
            return "Connected"
        }
        #elseif ($vpns.ConnectionStatus -eq "Disconnected") {
            #This will not be visable in regular use, because it is within a job. Leaving this here so that using start-transcript this can be seen for debugging in necessary
            #Write-Verbose ("ERROR: The vpn connection was unsucessful on try #$i Date:" + (Get-Date))
        #}
        if ($i -gt 3) {
            Start-Sleep -s 60 #Sleep for 1 min before retry
        }
    }
#If the connection was still unsucessfull make change to config file so that script will not connect to domain. As well script will notify at end that VPN + Domain have not been joined
    if ($vpns.ConnectionStatus -eq "Disconnected") {
        return "Generic_Error"
    }
}

function ConnectTo_Domain {
    param ([pscredential]$credential,[string]$domain_name)

    # Windows 10 home cannot be joined to a domain.
    $windows_edition = (Get-WindowsEdition -Online).edition
    if ($windows_edition -eq "Home")
    {
        return "Windows 10 Home"
    }

    $join_result = Add-Computer -Credential $credential -DomainName $domain_name -PassThru -ErrorVariable join_state
    $join_state_string = $join_state | Out-String
    switch ($join_state_string.replace("`n","").replace("`r","").replace(" ","")) {
        #Linebreaks and spaces are removed so that the error can be parsed correctly
        #without that the -match things "current password is `n incorrect" -and "current passowrd is incorrect" are totally different things
        {$_ -Match "currentpasswordisincorrect"}       {return "Access Denied"}
        {$_ -Match "usernameorpasswordisincorrect"}    {return "Access Denied"}
        {$_ -Match "alreadyinthatdomain"}              {return "Already Joined"}
        {$_ -Match "couldnotbecontacted"}              {return "Incorrect Configuration"}
    }
    if ($join_result.HasSucceeded)
        {
            return "Success"
        }
    return "Generic Error"
}

########################################################################################################################################################################
########################################################################### Begin the script ###########################################################################
########################################################################################################################################################################
"`n`n`n"
#####     Start script prep     #####
$VerbosePreference = "Continue" #Log Write-verbose to the transcript

###Because of get-eventlog not working in powershell 6 this script will not work
if ($PSVersionTable.PSVersion.Major -ge 6)
    {
        Throw @"
    
        
        This script does not support PowerShell 6+
        ------------------------------------------

        There may be other issues, but Get-EventLog, and other windows specific cmdlets
        do not work in PS Core. The likely fix is to use:
            https://github.com/PowerShell/WindowsCompatibility
        though that is not implemented into this script yet.

        
"@
    }

# Close MS Edge if open
$kill_edge = Start-Job  {
    function Kill_Edge {
        $edge = Get-Process "*Edge"
        if ($edge.ProcessName -eq "MicrosoftEdge") {Stop-Process $edge;break}
    }
    Kill_Edge 3
}
$progressBar = 'Closeing Mircosoft Edge . . . |','Closeing Mircosoft Edge . . . /','Closeing Mircosoft Edge . . . -','Closeing Mircosoft Edge . . . \' 
loading_animation $kill_edge $progressBar "Edge is Closed."

# Check for the config file & success log. In not create the log. Fail if the config file is missing
$wait = Start-Job -ScriptBlock {
    while (-not(Test-Path $ENV:USERPROFILE\Desktop\amnet_computer_setup\Config\smart.xml)) {Start-Sleep -Milliseconds 500}
}
$progressBar = 'Verifying setup folder is copied to desktop . . . |','Verifying setup folder is copied to desktop . . . /','Verifying setup folder is copied to desktop . . . -','Verifying setup folder is copied to desktop . . . \' 
loading_animation $wait $progressBar "The config file was found."

# Find the script log. If it does not exist, create one.
if (Test-Path "$Global:LogLocation\Success Log.xml") {
    [xml]$success_log = Get-Content "$Global:LogLocation\Success Log.xml"
} else {
    New-Item $Global:LogLocation -ItemType Directory
    New-Item "$Global:LogLocation\Success Log.xml" -ItemType File
    [xml]$success_log = @"
<?xml version="1.0" encoding="UTF-8"?>
<Log>
    <Script_Setup>
            <Status script_status="Not Attempted"></Status>
            <Results></Results>
            <reboot_number>0</reboot_number>
    </Script_Setup>
    <Misc_Start>
            <Status script_status="Not Attempted"></Status>
            <Results></Results>
            <reboot_number>0</reboot_number>
    </Misc_Start>
    <OEM_Updates>
            <Status script_status="Not Attempted"></Status>
            <Results></Results>
            <reboot_number>0</reboot_number>
    </OEM_Updates>
    <Windows_Updates>
            <Status script_status="Not Attempted"></Status>
            <Results></Results>
            <reboot_number>0</reboot_number>
    </Windows_Updates>
    <VPN>
            <Status script_status="Not Attempted"></Status>
            <Results></Results>
    </VPN>
    <Domain>
            <Status script_status="Not Attempted"></Status>
            <Results></Results>
    </Domain>
    <Application_Install>
            <Status script_status="Not Attempted"></Status>
            <Results></Results>
    </Application_Install>
    <Misc_End>
            <Status script_status="Not Attempted">This is a placeholder. Please Ignore</Status>
            <Results></Results>
    </Misc_End>
    <Script_Teardown>
            <Status script_status="Not Attempted"></Status>
            <Results></Results>
    </Script_Teardown>
</Log>
"@
    $success_log.Save("$Global:LogLocation\Success Log.xml")
}

#Wait for internet connection. This will be required each time.
$wait_for_internet_access = Start-Job  {
    $no_internet = $true
    while ($no_internet) {
        $ComputerName=$env:computername
        $networks = Gwmi -Class Win32_NetworkAdapter -ComputerName $computername
        foreach ($network in $networks) {
        $network , $network.NetConnectionStatus
            if ($network.NetConnectionStatus -eq 2) { #2 Means connected
                $no_internet = $false
                break
            } 
        }
        Start-Sleep -s 1
    }
}
$progressBar = 'Waiting for internet access . . . |','Waiting for internet access . . . /','Waiting for internet access . . . -','Waiting for internet access . . . \' 
loading_animation $wait_for_internet_access $progressBar "Internet Connecttion Successful"
[xml]$smart = Get-Content "$ENV:USERPROFILE\Desktop\amnet_computer_setup\Config\smart.xml" -ea 1
#Find out the last successful job from the setup. This is for recovery after crash, or purposefull reboot reboot, such as OEM/Windows Updates


########## - Create Logging - #########
Start-Transcript "$Global:LogLocation\transcript.txt" -IncludeInvocationHeader -Append


if ($success_log.Log.Script_Setup.Status.script_status -eq "Not Attempted")
{

    "Running Inital Setup requirements for the script."
    try
    {
        #Disable UAC so that installs will work without issue. Reenabled in cleanup.
        New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force -ErrorAction Stop
        $success_log = Update_Log @("Script_Setup","Results") "UAC successfully disabled"
        "UAC Temporarily Disabled for PC setup"
    }
    catch
    {
        $success_log = Update_Log @("Script_Setup","Status","Failed") "Unable to disable UAC via`n'New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force'`n Script requires disabling UAC to function."
        Throw "Unable to disable UAC via`n'New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force'`n Script requires disabling UAC to function.`n`n$_"
    }


    #Enable Powershell remoting for the local admin account
    try
    {
        try
        {
            Set-NetConnectionProfile -NetworkCategory "Private" -ErrorAction Stop
        }
        catch
        {
            #If script is wating on net connection in earlier step, it takes this command a few secconds to realize. Waiting so that it does not fail.
            Start-Sleep -s 10
            Set-NetConnectionProfile -NetworkCategory "Private" -ErrorAction Stop
        }
        "Set Network connection $((Get-NetConnectionProfile).InterfaceAlias) to 'Private' to enable PSRemoting"
        $VerbosePreference = "SilentlyContinue"
        Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop
        $trusted_psremoting_hosts | % {Set-Item wsman:\localhost\client\trustedhosts "$_" -Force -ErrorAction Stop}
        Set-Service -Name winrm -StartupType Automatic -ErrorAction Stop
        Start-Sleep -s 2
        Restart-Service WinRM -ErrorAction Stop
        "PSRemoting Enabled"
        $VerbosePreference = "Continue"
        $success_log = Update_Log @("Script_Setup","Results") "PS Remoting was succesfully enabled. Trusted computers: $trusted_psremoting_hosts"
    }
    catch
    {
        $script_setup_failed = $true
        $success_log = Update_Log @("Script_Setup","Results") "Enabling PSRemoting failed with error:`n$_"
    }

    if ($script_setup_failed)
    {
        $success_log = Update_Log @("Script_Setup","Status","Failed") "Initial requirements for the script failed. See results bellow for more information."
    }
    else
    {
        $success_log = Update_Log @("Script_Setup","Status","Completed") "Initial Requirements for the script were completed successfully."
    }
}


##### - Output the current progress of the script - #####
[xml]$success_log = Get-Content "$Global:LogLocation\Success Log.xml"

#Prep colors and reset variables
$inital_color = (Write_AsColor 6)[0]
$window_width = [Math]::Round((((Get-Host).UI.RawUI.MaxWindowSize).width), 0 ,"AwayFromZero")
$finish_header_text = ""
$finish_header = ""
$finish_header_output = ""

#Build the header for the colored SCRIPT RESULTS output
for ($i = 0; $i -lt ((Get-Host).UI.RawUI.MaxWindowSize).width; $i += 18)
{
    $finish_header += "In Progress . . . "
}
$finish_header = $finish_header.Substring(0,$window_width)
$finish_header_text += "#####SCRIPT STATUS FOR: $($env:COMPUTERNAME.ToUpper())#####"
while ($finish_header_text.Length -lt $window_width)
{
    $finish_header_text = $finish_header_text.Insert(5," ")
    $finish_header_text = $finish_header_text.Insert($finish_header_text.Length - 5," ")
}
if ($finish_header_text.Length -gt $finish_header.Length) {$finish_header_text = $finish_header_text.Substring(1,$finish_header.Length)}
$finish_header_output += "$finish_header`n$finish_header_text`n$finish_header"
Write-Output "`n`n$finish_header_output`n`n"

# Parse the Success Log.xml and output the results with color!
for ($node = $success_log.Log.FirstChild; $null -ne $node; $node = $node.NextSibling)
{
    if ($node.Status.script_status -eq "Completed") # log states that the section was completed successfully
    {
        Write_AsColor 10|Out-Null; "`n$($node.get_Name()): $($node.Status.script_status) - $($node.Status."#text")"; Write_AsColor $inital_color| Out-Null
    }
    else # log states that the section either failer, or was not attempted
    {
        Write_AsColor 12|Out-Null; "`n$($node.get_Name()): $($node.Status.script_status) - $($node.Status."#text")"; Write_AsColor $inital_color| Out-Null
    }
    try
    {
        $try_node = $node.Results.get_childnodes()
    }
    catch
    {
        $try_node = $null
    }
    if ($try_node)
    {
        for ($node2 = $node.Results.FirstChild; $null -ne $node2; $node2 = $node2.NextSibling)
            {
                Write-Output "     $($node2."#text")"
            }
    }
}
#The final line to close off the Script report section
Write_AsColor 6 | Out-Null; Write-Output "$finish_header"; Write_AsColor $inital_color| Out-Null


if ($success_log.Log.Misc_Start.Status.script_status -in @("Not Attempted","Run Again")) {
    "Running the Misc_Start commands."
    #This is the beginning of the config file. It allows for custom powershell commands to be run on a client to client or computer to computer basis without having to re-program this script
    for ($command = $smart.xml.commands_to_execute.misc_start.FirstChild; $null -ne $command; $command = $command.NextSibling) {
        $expression = parse_for_environment_variables $command.'#text'
        "$expression"
        Invoke-Expression "$expression" -ErrorAction Inquire
        if ($? -or ($LASTEXITCODE -eq 0)) { #If the invoked expression succceded
            if (-not($command.get_HasAttributes())) { #No success message but report success
                $success_log = Update_Log @("Misc_Start","Results") "$($command.get_Name())"
                Write-Output "$($command.get_Name()) succeded"
            } 
            else { #Report the given success message
                $success_log = Update_Log @("Misc_Start","Results") "$($command.SuccessMessage)" -ea 0
                Write-Output "$($command.SuccessMessage)"
            } 
        } else { #The invoke expression failed.

            if (($null -eq $Error[-1]) -and ($null -eq $LASTEXITCODE)) { #Possible ways that the called powershell could fail.
                $misc_error = "An unspecified error occured."
            } elseif ($null -ne $Error[-1]) {
                $misc_error = "$($Error[-1])"
            } else {
                $misc_error = "Application exited with code $LASTEXITCODE"
            }

            $success_log = Update_Log @("Misc_Start","Results") "$misc_error"
            Write-Host "$($Error[-1])"
            $misc_start_failed = $true
        }
        $LASTEXITCODE = $null #reset the exit code. This is incase the user is using powershell to call an application
    } #End for loop
    #Update the success log with if this section was a success or not.
    if ($misc_start_failed) {$success_log = Update_Log @("Misc_Start","Status","Failed") "All or none of the misc expressions was successful. Please see 'Success Log.xml' Misc_Start -> Result to see which expression failed."}
    else {$success_log = Update_Log @("Misc_Start","Status","Completed") "All commands in the Misc_Start section of the smart.xml config were succesful"}
}
#Install the dell drivers. It is important that this comes first
#This switch is missing a LOT of return codes for DCU CLI, most of those will not be used, but would be nice to have for logging purposes.
if($success_log.Log.OEM_Updates.Status.script_status -in @("Not Attempted","Run Again","In Progress"))
{
    if([int]$success_log.Log.OEM_Updates.reboot_number -lt 5)
    {
        if ((get-ciminstance -ClassName Win32_ComputerSystem).Manufacturer -eq "Dell Inc.")
        { #Check if it is a dell system
            "This is a Dell Machine. Beginning Dell Updates"
            switch (Update-DellDrivers) { #Running dell updates silently is not supported in this script.
                #In progress
                0 {$success_log = Update_Log @("OEM_Updates","Status","Run Again","+1") "dcu-cli ran successfully. It apprears that all firmare udpates have been installed. Will still restart and run dcu-cli again of excess of caution."; Restart-ComputerAndWait}
                1 {$success_log = Update_Log @("OEM_Updates","Status","Run Again","+1") "Not Finished"; Restart-ComputerAndWait} # A reboot is required to finish the install.

                #Success
                500 {$success_log = Update_Log @("OEM_Updates","Status","Completed") "No more Dell updates with current configuration"; Restart-ComputerAndWait} #reboot for fun

                #Failure
                $null {$success_log = Update_Log @("OEM_Updates","Status","Failed") "No value was returned. Likely that DCU-CLI never launched. No OEM updates installed."}
                2 {$success_log = Update_Log @("OEM_Updates","Status","Run Again","+1") "An unknown application error has occurred, return code 2. No OEM updates installed."; Restart-ComputerAndWait}
                3 {$success_log = Update_Log @("OEM_Updates","Status","Failed") "This is not a Dell machine. This script only supports dell machines at the moment. No OEM udpates installed."}
                4 {$success_log = Update_Log @("OEM_Updates","Status","Failed") "Dell updates failed because they were lanuched without admin privledges. No OEM updates installed."}
                6 {$success_log = Update_Log @("OEM_Updates","Status","Failed") "Somehow 2 instances of dcu-cli launched. No OEM updates installed."}
                7 {$success_log = Update_Log @("OEM_Updates","Status","Failed") "The application does not support the current system model. No OEM updates installed."}
                "Failed to Launch" {$success_log = Update_Log @("OEM_Updates","Status","Failed") "DCU-CLI.exe failed to launch. No updates installed."}
                "DCU-CLI application missing" {$success_log = Update_Log @("OEM_Updates","Status","Failed") "Install apprears to have failed, or DCU-CLI is now installed in a location other than 'C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe'. No OEM updates installed."}
                "Report not Created" {$success_log = Update_Log @("OEM_Updates","Status","Failed") "DCU CLI either failed to run, or failed to create the log file. No OEM updates installed."}
                "Failed to install" {$success_log = Update_Log @("OEM_Updates","Status","Failed") "Failed to install dell command update. No OEM installed."}
                default {$success_log = Update_Log @("OEM_Updates","Status","Failed") "Unknown Error returned code $_. No OEM updates installed."}

            }
        } 
        elseif ((get-ciminstance -ClassName Win32_ComputerSystem).Manufacturer -eq "LENOVO")
        {
            if ($success_log.Log.OEM_Updates.Status.script_status -eq "Not Attempted")
            {
                $success_log = Update_Log @("OEM_Updates","Status","In Progress") "Lenovo updates are being installed. If this message is seen at the finish of the script, then assume lenovo updates has failed, and install manually."
            }
            switch (Install-ScriptLenovoUpdate) {
                #Success
                0 {$success_log = Update_Log @("OEM_Updates","Status","Completed") "All current Lenovo firmware updates installed successfully"}

                #In Progress
                1 {$success_log = Update_Log @("OEM_Updates","Status","Run Again","+1") "Rebooting, then installing more Lenovo updates."; Restart-ComputerAndWait}

                #Failure
                "Module Install Success, Update Failure" {$success_log = Update_Log @("OEM_Updates","Status","Failed") "The Powershell Module LSUClient Update was successfully installed, but the Lenovo firmware updates themseleves failed for an unknown reason."}
                "Module Install Failure" {$success_log = Update_Log @("OEM_Updates","Status","Failed") "Install of the Powershell Module LSUClient failed. No Lenovo firmware udpates were installed."}
            }
        }
        else
        { #The Manufacturer is not recognized. No firmware updates installed. 
            $success_log = Update_Log @("OEM_Updates","Status","Failed") "The manufacturer of this computer is not recognized by this computer. Currently only Dell/Lenovo/Microsoft firmware updates are supported. No OEM updates installed. Please install manually."
        }
    }
    else
    {
        $success_log = Update_Log @("OEM_Updates","Status","Failed") "The computer has run and rebooted the OEM updates 5 times. It is likely that the setup is in a loop, and not returning success nor failure. Breaking the loop so the script can finish.`nPrevious message here was:`n$($success_log.Log.OEM_Updates.Status.'#text')"
    }
}

#Install windows Updates if all updates not installed. Reboot if reboot needed.
#I know that this should be an if statement. I am leaving it as a switch for legibility purposes so it is the same as the dell updates, and allows for more return values in the future.
if ($success_log.Log.Windows_Updates.Status.script_status -in @("Not Attempted","Run Again","In Progress"))
{
    if([int]$success_log.Log.Windows_Updates.reboot_number -lt 5)
    {
        "Installing Windows Updates . . ."
        $windows_updates = $null
        if ($success_log.Log.Windows_Updates.Status.script_status -eq "Not Attempted")
        {
            $success_log = Update_Log @("Windows_Updates","Status","In Progress") "Windows updates are being installed. If this message is seen at the finish of the script, then assume windows updates has failed, and install manually."
        }
        $windows_updates = Install-ScriptWindowsUpdate
        switch ($windows_updates) {
            #Success
            {$_ -eq 0}                                           {$success_log = Update_Log @("Windows_Updates","Status","Completed") "All current updates installed successfully";Restart-ComputerAndWait}
            #Need a windows machine to test what the manufacturer value for this is.
            #{$null} {$success_log = Update_Log @("Windows_Updates","Status","Completed") "All current updates installed successfully."; $success_log = Update_Log @("OEM Updates", "Status") "OEM updates installed as part of the Windows Updates."}

            #In Progress
            {$_.count -gt 0}
                                                                {
                                                                    foreach ($update in $windows_updates) {
                                                                        if ($update)
                                                                        {
                                                                            if ($null -eq $update.KB) {$KB = "No KB"} else {$KB = $update.KB}
                                                                            $success_log = Update_Log @("Windows_Updates","Results") "$($update.Result) - $KB - $($update.Title)"
                                                                        }
                                                                    }
                                                                    $success_log = Update_Log @("Windows_Updates","Status","Run Again") "Rebooting, then installing more updates."
                                                                    Restart-ComputerAndWait
                                                                }

            #Failure
            {$_ -eq 1}                                           {$success_log = Update_Log @("Windows_Updates","Status","Failed") "All of the attempted updates this reboot failed."}
            {$_ -eq "Module Install Success, Update Failure"}    {$success_log = Update_Log @("Windows_Updates","Status","Failed") "The Powershell Module PSWindows Update was successfully installed, but the updates themseleves failed for an unknown reason."}
            {$_ -eq "Module Install Failure"}                    {$success_log = Update_Log @("Windows_Updates","Status","Failed") "Install of the Powershell Module PSWindowsUpdate failed. No windows udpates were installed."}
            default                                              {$success_log = Update_Log @("Windows_Updates","Status","Failed") "Unknown Error. Returned valued: '$_'"}
        }
    }
    else
    {
        $success_log = Update_Log @("Windows_Updates","Status","Failed") "The computer has run and rebooted the windows updates 5 times. It is likely that the setup is in a loop, and not returning success nor failure. Breaking the loop so the script can finish.`nPrevious message here was:`n$($success_log.Log.Windows_Updates.Status.'#text')"
    }
}

########## - Connect to VPN and Domain if required by the config file - ##########

# create an array of functions needed for the Domain/VPN join script
if ($success_log.Log.Domain.Status.script_status -in @("Not Attempted")) #Domain join is done last. If it is completed, warning, or failed, then this has already been run, so dont bring up on next reboot
{
    $export_functions = [scriptblock]::Create(@"
    Function Update_Log { $function:Update_Log }
    Function Get_UserPass {$function:Get_UserPass}
    Function ConnectTo_VPN {$function:ConnectTo_VPN}
    Function ConnectTo_Domain {$function:ConnectTo_Domain}
"@)

    if (($smart.xml.client_config.vpn.server_address -ne "") -or ($smart.xml.client_config.domain.domain_name -ne "")) { #If domain name and vpn server address are empty that means that none of this below is necessary.
        $join_domainvpn = Start-Job -Name "Domain + VPN Job" -ScriptBlock {
            Param ([string]$Global:LogLocation,[xml]$smart)
            $cred_array = Get_UserPass "Admin Password" " Please Enter the Amnet_Admin password.`nThis will be used for Domain and VPN login."
            [xml]$smart = Get-Content "$ENV:USERPROFILE\Desktop\amnet_computer_setup\Config\smart.xml"
            #Convert the Password to PSCredential Object
            $password = $cred_array[1] | ConvertTo-SecureString -asPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($cred_array[0], $password)
            if ($smart.xml.client_config.domain.domain_name -ne "")
                {
                    $credential = New-Object System.Management.Automation.PSCredential("$($smart.xml.client_config.domain.domain_name)\$($cred_array[0])", $password)
                }
            
            #Connect the the VPN
            $vpn_server_address = $smart.xml.client_config.vpn.server_address
            if ($vpn_server_address) { #If no server address, the just connect to the domain. Skip this
                $vpn_state = $null
                while ($vpn_state -in ($null,"Username_or_Password_Failure"))
                {
                    $vpn_state = ConnectTo_VPN $true $cred_array[0] $cred_array[1]
                    switch ($vpn_state) {
                        #success
                        "Connected"                     {$success_log = Update_Log @("VPN","Status","Completed") "Successfully connected to the VPN ($vpn_server_address)."}
                        
                        #failure and retry
                        "Username_or_Password_Failure"  {
                                                            $success_log = Update_Log @("VPN","Status","In Progress") "The given credentials were not accepted. Access Denied to $vpn_server_address"
                                                            $cred_array = Get_UserPass "Admin Password" "Either the Username or Password is Incorrect." "red"
                                                        }
                        
                        #failure and continue
                        "Generic_Error"                 {$success_log = Update_Log @("VPN","Status","Failed") "The VPN join to $vpn_server_address failed with an unspecified error."}
                        "VPN Creation Failed"           {$success_log = Update_Log @("VPN","Status","Failed") "Unable to create the VPN $vpn_server_address. Configuration in smart.xml is likely wrong."}
                        default                         {$success_log = Update_Log @("VPN","Status","Failed") "The Vpn join to $vpn_server_address failed catastrophically.`n Returned:`n $_"}
                    }
                }
            }
            # This is a workaround. Need to figure out vpn connection with PSCredential object.
            Remove-Variable cred_array #Try to keep passwords in ram for as little time as possible

            
            if ($smart.xml.client_config.domain.domain_name) { #If there is some domain name listed, so connect to the domain.
                if ($success_log.Log.VPN.Status.script_status -notlike "Failed") { #If the vpn connection failed, and the vpn is required to join the domain, then don't try
                    $domain_name = $smart.xml.client_config.domain.domain_name
                    switch (ConnectTo_Domain $credential $domain_name) {
                        #warning
                        "Already Joined"                {$success_log = Update_Log @("Domain","Status","Warning") "This computer was already joined to $domain_name. The given domain in the smart.xml config was the same as the Domain the computer was already joined to."}
                    
                        #Success
                        "Success"                       {$success_log = Update_Log @("Domain","Status","Completed") "The Domain join to $domain_name was successful."}
                        
                        #failure
                        "Access Denied"                 {$success_log = Update_Log @("Domain","Status","Failed") "The UserName or password was incorrect. Access Denied. Domain Join to $domain_name failed"}
                        "Generic Error"                 {$success_log = Update_Log @("Domain","Status","Failed") "The Domain join to $domain_name failed for an unknown reason. Generic Error. This computer is not joined to a domain."}
                        "Incorrect Configuration"       {$success_log = Update_Log @("Domain","Status","Failed") "Unable to join $domain_name. The specified domain either does not exist or could not be contacted."}
                        "Windows 10 Home"               {$success_log = Update_Log @("Domain","Status","Failed") "Unable to join $domain_name. Windows 10 Home is installed. Windows 10 Home machines cannot join a domain."}
                        default                         {$success_log = Update_Log @("Domain","Status","Failed") "SCRIPT ERROR. Please let the script maintainer know about this error. No known result was returned from ConnectTo_domain. Assume that Domain join to $domain_name failed for an unknown reason.`nReturned:`n$_"}
                    }
                } else {
                        $success_log = Update_Log @("Domain","Status","Failed") "The Domain join was not attempted, because the smart.xml config file states that a VPN is required to connect, and that failed."
                }
            } else { #Domain join was skipped, because domain name was not listed.
                $success_log = Update_Log @("Domain","Status","Warning") "Domain join was not specified by the smart.xml config file. No domain joined."
            }
        } -InitializationScript $export_functions -ArgumentList "$Global:LogLocation",$smart #Look above this job for what the $export_functions is.
    } else { #The whole DomainVPN section was skipped, because neither domain not vpn server were listed.
        $success_log = Update_Log @("VPN","Status","Warning") "A VPN connection was not required as specified by the smart.xml config file."
        $success_log = Update_Log @("Domain","Status","Warning") "Domain join was not specified by the smart.xml config file. No domain joined."
    }
} # End if domain in "Not attempted"

########## - Wait for VPN join if necessary - ##########
#A second job needs to be created to monitor if the VPN job fails, and restart if if necessary
#The check for the VPN connection is done before software is installed. That way, if any of the software that needs to be installed is stored on the domain, that path can be accessed
if (($join_domainvpn.State) -eq "Running") { #If the VPN job is still running. If not there, either done somehow, or never started.
    $wait = Start-Job -Name "Wait for Domain + VPN" -ScriptBlock {
        param([xml]$smart, [xml]$success_log, [string]$Global:LogLocation)
        while ($true)
            {
                [xml]$success_log = Get-Content "$Global:LogLocation\Success Log.xml" #needs to get each loop, so that when updated by domainVPN job this can then grab that update
                Start-Sleep -s 1
                if (($smart.xml.client_config.vpn.server_address -ne "") -and ($smart.xml.client_config.domain.domain_name -ne "")) # Domain and VPN are resuired
                    {
                        if (($success_log.Log.VPN.Status.script_status -in @("Completed","Failed")) -and ($success_log.Log.Domain.Status.script_status -in @("Completed","Warning","Failed")))
                            {
                                Break
                            }
                    }
                elseif ($smart.xml.client_config.domain.domain_name -ne "")
                    { #just domain is required
                        if ($success_log.Log.Domain.script_status -in @("Completed","Warning","Failed")) {New-Item "C:\Users\amnet_admin\Desktop\shouldbreak.txt" -ItemType File;Break}
                    }
                else #just vpn is required
                    {
                        if ($success_log.Log.VPN.script_status -in @("Completed","Failed")) {New-Item "C:\Users\amnet_admin\Desktop\shouldbreak.txt" -ItemType File;Break}
                    }
                Start-Sleep -s 1
            }
    } -ArgumentList $smart,$success_log,$Global:LogLocation
    $progressBar = '| Waiting for the Domain/VPN join to finish . . .','/ Waiting for the Domain/VPN join to finish . . .','- Waiting for the Domain/VPN join to finish . . .','\ Waiting for the Domain/VPN join to finish . . .' 
    loading_animation $wait $progressBar "Doman/VPN Join PS Job has finished"
}

if ($join_domainvpn.State -eq "Failed") {
    Update_Log @("Domain","Status","Failed") "The Domain/VPN job failed. Assume that the VPN, Domain join, and all dependencies of both failed."
    Write-Error "The Domain/VPN job FAILED"
}

#Restart-Computer -Force #not sure why this is needed to fix the script. for some reason after the domain join the computer is not going right into the software install, after reboot it does though
########## - Install all software EXACTLY as listing in smart.xml - ##########
if ($success_log.Log.Application_Install.Status.script_status -in @("Not Attempted","In Progress"))
{
    "Starting Application Install . . ."
    $success_log = Update_Log @("Application_Install","Status","In Progress") "Currently installing applications. If this is seen at the end of the script, assume that the installs failed."
    for ($install = $smart.xml.commands_to_execute.programs_to_install.FirstChild; $null -ne $install; $install = $install.NextSibling)
    {
        switch (Install-Software $install.program_name $install.install_location $install.wait_for_event $install.wait_each_attempt $install.install_switch) {
            #Success
            "Installed Successfully"    {$success_log = Update_Log @("Application_Install","Results") "$($install.program_name) was successfully installed"}
            
            #failed
            "Path Not Found"            {
                                            $success_log = Update_Log @("Application_Install","Results") "$($install.program_name) failed to install. Installer not found at path given in smart.xml ($($install.install_location))"
                                            $application_install_failed = $true #One or more of the application installs failed.
                                        }
            default                     {
                                            $success_log = Update_Log @("Application_Install","Results") "$($install.program_name) FAILED to install.`nReturned:`n$_"
                                            $application_install_failed = $true #One or more of the application installs failed.
                                        }
        }
    }
    if ($application_install_failed) {$success_log = Update_Log @("Application_Install","Status","Failed") "One or more of the applications failed to install."}
    else {$success_log = Update_Log @("Application_Install","Status","Completed") "All software was installed without error."}
}


if ($success_log.Log.Misc_End.Status -in @("Not Attempted","Run Again")) {
    "Running the Misc_Start commands."
    #This is the beginning of the config file. It allows for custom powershell commands to be run on a client to client or computer to computer basis without having to re-program this script
    for ($command = $smart.xml.commands_to_execute.misc_end.FirstChild; $null -ne $command; $command = $command.NextSibling)
    {
        $expression = parse_for_environment_variables $command.'#text'
        "$expression"
        Invoke-Expression "$expression" -ErrorAction Inquire
        if (-not($?) -or ($LASTEXITCODE -eq 0))
        { #If the invoked expression succceded
            if (-not($command.get_HasAttributes()))
            { #No success message but report success
                [xml]$success_log = Update_Log @("Misc_End","Results") "$($command.get_Name())"
                Write-Output "$($command.get_Name()) succeded"
            } 
            else
            { #Report the given success message
                [xml]$success_log = Update_Log @("Misc_End","Results") "$($command.SuccessMessage)"
                Write-Output "$($command.SuccessMessage)"
            } 
        }
        else
        { #The invoke expression failed.

            if (($null -eq $Error[-1]) -and ($null -eq $LASTEXITCODE))
            { #Possible ways that the called powershell could fail.
                $misc_error = "An unspecified error occured."
            }
            elseif ($null -ne $Error[-1])
            {
                $misc_error = $Error[-1]
            }
            else
            {
                $misc_error = "Application exited with code $LASTEXITCODE"
            }

            [xml]$success_log = Update_Log @("Misc_End","Results") "$($misc_error)"
            Write-Host "$($Error[-1])"
            $misc_end_failed = $true
        }
        $LASTEXITCODE = $null #reset the exit code. This is incase the user is using powershell to call an application
    } #End for loop
    #Update the success log with if this section was a success or not.
    if ($misc_end_failed) {$success_log = Update_Log @("Misc_End","Status","Failed") "All or none of the misc expressions was successful. Please see 'Success Log.xml' Misc_Start -> Result to see which expression failed."}
    else {$success_log = Update_Log @("Misc_End","Status","Completed") "All commands in the Misc_Start section of the smart.xml config","Completed"}
}

########## - Teardown - ##########
if ($success_log.Log.Script_Teardown.Status.script_status -eq "Not Attempted") {
    # Enable UAC
    try
    {
        Set-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -Value 1 -Force -ErrorAction Stop
        "UAC Re-Enabled"
        $success_log = Update_Log @("Script_Teardown","Results") "Re-Enabling UAC was successful."
    }
    catch
    {
        $teardown_failed = $true
        $success_log = Update_Log @("Script_Teardown","Results") "Re-Enabling UAC Failed. Please cahnge UAC notify settings to desired status."
    }

    #Disable & Remove PS Remoting
    try
    {
    Disable-PSRemoting -Force -ErrorAction Stop
    Remove-Item -Path WSMan:\localhost\listener\listener* -Recurse -ErrorAction Stop
    Set-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -Enabled False -ErrorAction Stop
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system -Name LocalAccountTokenFilterPolicy -Value 0 -ErrorAction Stop
    Stop-Service WinRM -ErrorAction Stop
    Set-Service -Name winrm -StartupType Disabled -ErrorAction Stop
    $success_log = Update_Log @("Script_Teardown","Results") "Disabling Powershell Remoting was successful."
    }
    catch
    {
        $teardown_failed = $true
        $success_log = Update_Log @("Script_Teardown","Results") "Disabling Powershell Remoting failed. Please disable manually."
    }

    #Remove the press enter job because it is no longer useful.
    Stop-Job "Mr. Press Enter"
    Remove-Job "Mr. Press Enter"
    $success_log = Update_Log @("Script_Teardown","Status","Completed") "Script cleanup was completed successfully."

    if ($teardown_failed)
    {
        $success_log = Update_Log @("Script_Teardown","Status","Failed") "$($ERROR[-1])`nRead the messages below to see failures."
    }
}

########## - Output Results - ##########

[xml]$success_log = Get-Content "$Global:LogLocation\Success Log.xml"

#Prep colors and reset variables
$inital_color = (Write_AsColor 3)[0]
$window_width = [Math]::Round((((Get-Host).UI.RawUI.MaxWindowSize).width), 0 ,"AwayFromZero")
$finish_header_text = ""
$finish_header = ""
$finish_header_output = ""

#Build the header for the colored SCRIPT RESULTS output
for ($i = 0; $i -lt ((Get-Host).UI.RawUI.MaxWindowSize).width; $i++)
    {
        $finish_header += "#"
    }
$finish_header_text += "#####SCRIPT RESULTS FOR $($env:COMPUTERNAME.ToUpper())#####"
while ($finish_header_text.Length -lt $window_width)
    {
        $finish_header_text = $finish_header_text.Insert(5," ")
        $finish_header_text = $finish_header_text.Insert($finish_header_text.Length - 5," ")
    }
if ($finish_header_text.Length -gt $finish_header.Length) {$finish_header_text = $finish_header_text.Substring(1,$finish_header.Length)}
$finish_header_output += "$finish_header`n$finish_header_text`n$finish_header"
Write-Output "`n`n$finish_header_output`n`n"

# Parse the Success Log.xml and output the results with color!
for ($node = $success_log.Log.FirstChild; $null -ne $node; $node = $node.NextSibling)
    {

    if ($node.Status.script_status -eq "Completed") # log states that the section was completed successfully
        {
            Write_AsColor 10|Out-Null; "`n$($node.get_Name()): $($node.Status.script_status) - $($node.Status."#text")"; Write_AsColor $inital_color| Out-Null
        }
    else # log states that the section either failer, or was not attempted
        {
            Write_AsColor 12|Out-Null; "`n$($node.get_Name()): $($node.Status.script_status) - $($node.Status."#text")"; Write_AsColor $inital_color| Out-Null
        }
    if ($null -ne $success_log.Log.Misc_start.Results.get_childnodes())
    {
        for ($node2 = $node.Results.FirstChild; $null -ne $node2; $node2 = $node2.NextSibling)
            {
                Write-Output "     $($node2."#text")"
            }
    }
    }
#The final line to close off the Script report section
Write_AsColor 3 | Out-Null; Write-Output "$finish_header"; Write_AsColor $inital_color| Out-Null

########## - Notes - ##########

### Fix
#If the wrong password is enterd, the script doesn't re-try vpn connection - this should be fixed. Needs to be tested.

#Script needs to be able to notifiy that the OEM updates are installed for windows  machines as part of the windows udpate.
    # The return value is done in the switch. I just need to add that check in the Windows-Update function itself.

# Mr. Press Enter does not apprear to be working.


### Add
# The dell command update uses start-process -PassThru, I need to see if using that on the software install if that can monitor the install process for the software_install function.
    # It is totally possible to wait for a program to install with (Get-Process "process name").WaitForExit()  . . . wish I knew that eariler :/

#Add option in smart.xml to disable psremoting
#application installs should have the applity to add custom required commands before install. 
    # for-example for COF mount the office 2016 volume license

#script needs the abiliy to omit specific dell/microsoft/lenovo updates
# script needs to be able to log exactly what dell/microsoft/lenovo updates have been installed.

# Should be able to change the save location of the logging files via switch.

# This should have the ability to be run from a remote computer. i.e. run headless there are multiple ways that this could be accomplished
    # Still run everything local, but allow for a user to PS-Remote to it. This would mean that everything writes to a file, and the PS-Remote just reeds that file. Which the main setup could then read that file, allowing the two to talk to eachother - this is my favorite
        #What will probably work the best, is script will wait ~5mins before starting up with the defaults, in those ~5mins the controller computer could connect to it, and then force a different smart.xml file.
    # The whole script could be called via the remote session
    # The whole setup could be run from a remote computer, that acts like a server, then the person setting up the computer could remote into the server.




##COMPUTER EASE SUCKS
# "Ending Session 1"
