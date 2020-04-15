# Windows Computer Setup Script
### A highly configurable Script to automate comptuer setups for MSPs and IT departments

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
* This script uses an answerfile. Answer files require that the infstll meadia uses a install.wim. If the windos iso comes with an install.esd that mist be converted otherwise the answer file will not work.
