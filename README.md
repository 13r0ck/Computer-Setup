# Windows Computer Setup Script
### A highly configurable Script to automate comptuer setups for MSPs and IT departments

### Script Logic
Below is the logic that the script goes through to setup a computer. Each section below (exculding the "Every restart") have different states that they can be in "Not Attempted", "In Progress", "Finished", or "Failed". These states are read from "Success Log.xml" and displayed in the "Output script progress" and "Final Output". The script will check each section sequentially for if action is required after every boot of the system. If the state is "Not Attempted" or "In Progress" that section of the script will be run. For both "Finished" or "Failed" that section of the script will not be run. The difference between "Finished" and "Failed" is the color of the "Final Output" and the "Ouput" sections of the script.

* Every restart
	* Check for PS6+
	* Close MS Edge, so that script is imediatly viable (Really only afffects first startup, but checks every time anyway)
	* Checks that smart.xml is in \Desktop\amnet_computer_setup\Config\smart.xml
	* Checks for Success Log.xml in $Global:LogLocation
	* Checks that the computer has internet access (via what the network addapter is reporting)
	* Starts/appends the global transcript. This is just a txt file of all that is printed to console

* Script Setup
	* Disables UAC via reg edit, so script runs in future reboots.
	* Enables PSRemoteing (not fully implemented, hard coded to trust only my computer name)
* Output the script progress *runs every restart*
* Misc Start
	* Sequentialy runs all commands in the mist_start part of \Config\smart.xml
* OEM Updates
	* Identifies if Dell/Lenovo Machine and installs them.
	* The computer will reboot many times, and the script will skip Script Setup, and Misc Start, and just continue with updates
	* This process will repeat until OEM updates return no results, then reboot one more time.
	* There is no login to "time out" on reboots. If an update fails every time, then the script will restrt the computer indefinetly.
* Windows Updates
	* Logic is identical to OEM updates, just install windows updates.
	* I am not sure if this will install windows Builds, never tried. I doubt it though.
* VPN Domain Job
	* This is a separate job that runs in the background.
	* The main portion of the script will wait until this section returns success or failure.
	* This is the part that brings up the username/password prompt.
		* Currently the prompt will identify an incorrect password, and ask again with a different ui making it obvious the password is wrong. Though the logic is broken. Entering the correct password in the second prompt will still fail.
	* Because this is run as a job it should be fairly easy to move the portion where the script waits to wherever you want
	* It was designed as a job so that it would be possible to install applications that do not require a VPN at the same time that the prompt is asking for user/pass
	* VPN Connection
		* This works with both PPTP and L2TP, but please don't use PPTP!
	* Domain Join
		* This has the logic to require the VPN or not. This can be specified in Config\smart.xml
	* While these are logically the same block, they will report separate success/fail in the "Success Log.xml"
* Application installs
	* Follows the install logic put in Config\smart.xml
	* Unfortunatly this does not support exit codes, and only works with windwos "information event logs"
	* Each install is allowed to fail 2 times before the script reports that the install was a failure
	* It is also possible to specifiy a time out in Config\smart.xml
	* There is not logic to check for if an application is already installed. If the "Application Installs" runs again (because of reboot or other reason), it will attempt to install applications again
* Mic End
	* This is meant to be the same as "Misc Start", though that was never finished, and this is currently disabled.
* Script Teardown
	* Re-enables UAC via reg edit
	* Diasables PSRemoting
* Final Output
	* There is one final output of the results of the script, successes/failues.
	* The final outoput is colored cyan, which is difrrent from the other log outputs.

## Needs to be done manually
* Login to domain admin account, and delete the local admin account
	* If there is not a domain/cannot connect then put a password on the local admin
* Connect with screen connect to verify functionality
* If possible conenct to the end users domain account remotely

## Notes for Windows Builds
* This script uses an answerfile. Answer files require that the install meadia uses a install.wim. If the windows iso comes with an install.esd that must be converted otherwise the answer file will not work.

## smart.xml documentation
* The best place to see how to configure smart.xml is the top half of the file is a comment that explains how each of the tags are ment to be used. You can configure the file however you would like, and you can view the examples provided in the file.

## autouuattend.xml
* This is just an answerfile that is supported by Windows 10, not my own creation.
* Read more about answerfiles [here](https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/wsim/answer-files-overview)
* The important modification to the answer file are syncronous commands 5 and 6. These allow for this script to run, eventhough it is not signed. (Sorry I will fix that soon!) As well as create a reg edit so that the batch file is called each reboot of the computer.
* The configuration of this answer file is to clear the drive and install windows with the C:\ drive taking the whole drive size. Feel free to change that as you wish

# How do I use this script?
* So far this has only been tested using a flashdrive as the boot medium that then installs windows. This script is configured so that changing the install path on a few files (autounattend/stat.bat/smart.xml) should allow for use on a PXE server, but I have never tried that.
* Download the newest Windows 10 ISO with the [media creation tool](https://www.microsoft.com/en-us/software-download/windows10)
* If that ISO contains a install.wim, then just make a bootable flashdrive from that ISO. I recommend [rufus](https://github.com/pbatard/rufus) for that.
* If the ISO contains an install.esd you can use my other repository to convert that to an install.wim, then create a bootable USB with that converted ISO
* Then copy this repository to the root of the flash drive. start.bat, the ps1, folders etc should be on the root. Follow the same folder stucture as this repository on the flash drive.
* Then disable secure boot (you can enable it after the setup is done. I recommend it), and boot to the flash drive. I often used dell machines that had had the option to change the boot order for on boot (F12). Then UEFI boot to the partiion with the install media (If you use rufus this will be partition 2).
	* If you do not have the option to change the boot order for on single boot see the section below about boot loops.
* The computer should then install Windows, and then complete all steps above.

# Help everything is broken!
* Category
	* Question
		* Answer
* The computer is in a boot loop!
	* The computer keeps looping on the purple/blue windows install screen? I have not yet seen the desktop
		* This likely means that the boot order was changed. Make sure that the drive that Windows is being installed on is the first in boot order. I(f the computer has the ability to select a one time boot instead. If it does not, then you are going to have to boot once, finish the windows install, then change the boot order so that the drive is first
	* The script is stuck rebooting to windows and then the same section of the script!
		* You can manually tell the script to skip a section by changing the \Log location (default is the desktop)\Log\Success Log.xml tag <Status script_status="In Progress"> to <Status script_status="Failed">, and that will tell the script to ignore that section after the next reboot. Then please create an issue here on github (Attach all files in the \Log location\Log) and I will look into the issue for you.
* The Command Prompt stops showing updates, the script basically stops?
	* I am still looking into remediating this. Try clicking on the windows then pressing the enter key, the command prompt should update, and then continue with the script.
* The issue I am having is not here!
	* Please create an issue here (On the issues tab) and provide me with both the transcript.txt and the "Success Log.xml" (usually \Desktop\Log)and I will see what I can do for you!
