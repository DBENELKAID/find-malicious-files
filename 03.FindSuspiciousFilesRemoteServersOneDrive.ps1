<#
Script Name 	:03.FindSuspiciousFilesRemoteServersOneDrive.ps1
Description		:PowerShell script that scans a drive to find malware files listed in the list below.
                :and when a suspicious file is found, it will be noted with the "MD5", SHA1 and SHA256 in a result file "Drive\:SuspiciousFileFound.txt".
				:the first files listed in this list are recent, some of which were used by russia to attack ukraine in February 23, 2022.
Model			:One drive - Running on remote machine (Remote-Job) - (Windows Server and Windows Workstation).
PSVersion	    :Windows PowerShell 4.0 and later, PowerShell Core.
Author			:Driss BENELKAID
Mail			:benelkaid.driss@outlook.fr - benelkaid.d@gmail.com
<<<<<<< HEAD
Version			:2.1
Created			:14/03/2022 - 16h00
Last modified	:04/12/2024 - 15h00
Shared script	:https://github.com/DBENELKAID/find-malicious-files.git
=======
Version			:2.0
Last modified	:14/03/2022 - 16h00
Shared script	:https://drive.google.com/drive/folders/1c-os1kTanb5mr_n9GJae7SZ7q5EEeZ3N?usp=sharing
>>>>>>> b229bb5551fd983369f248d36476868d66de88c1
				:It is allowed to modify this script to improve it and share it in order to mitigate cyberattaques.
#>
"PowerShell running in version: $($PSVersionTable.PSVersion)."

# ==================== Servers list ========================================================================
#
$PathList =  "C:\Scripts\ServersList.txt"
$Script:ServersList =  Get-Content -Path ${PathList}

# ==================== Ping ================================================================================
    Write-Host "<<<<<<<<<<<<<<<<<<<< Test-Connection (Ping) >>>>>>>>>>>>>>>>>>>>" -ForegroundColor Cyan
     
    function Ping {
 
        foreach (${Server} in ${ServersList}) {
            $Count1 = Test-Connection -ComputerName ${Server} -Quiet -Count 1 -ErrorAction SilentlyContinue
                if (${Count1} -like $true) {
                    Write-Host " ${Server} ping Ok [;-) " -ForegroundColor Green
                }
                elseIf (${Count1} -like $false) {
                    $Count2 = Test-Connection -ComputerName ${Server} -Quiet -Count 2 -ErrorAction SilentlyContinue
                        if (${Count2} -like $true) {
                            Write-Host " ${Server} ping Ok [;-) " -ForegroundColor Green
                        }
                        else {
                            Write-Host " ${Server} ping nOk [:-( " -ForegroundColor Red
                        }
                }
		} 
	}
Ping # function Ping


	Write-Host
	Write-Host "<<<<<<<<<<<<<<<<<<<< Remote jobs run >>>>>>>>>>>>>>>>>>>>" -ForegroundColor Cyan
#region ==================== Remote jobs run ===============================================================

    foreach ($Server in ${ServersList}) {
    Start-Sleep 1
    Write-Host "${Server} " -ForegroundColor Cyan
    Write-Host

    $JobName = "FindSuspiciousFiles"
	
	# Invoke-Command with Remote-Job
    Invoke-Command -ComputerName ${Server} -AsJob -JobName $JobName -ScriptBlock {

        $COMPUTERNAME  = $Env:COMPUTERNAME
        ${GetDate} = Get-Date -Format "dd/MM/yyyy HH:mm:ss"

#region list
# ==================== Indicators of compromise list =======================================================
# You can add other files to this list
$SuspiciousFiles = @(
'clean.exe',
'cl.exe',
'cl64.dll',
'cld.dll',
'cll.dll',
'conhosts.exe',
'c9EEAF78C9A12.dat',
'XqoYMlBX.exe',
'HermeticWiper.exe',
'Stage1.exe',
'Stage2.exe',
'Tbopbh.jpg',
'com.exe',
'cc2.exe',
'depended.exe',
'deputy.exe',
'dessert.exe',
'deep-thinking.exe',
'demanded.exe',
'deep-versed.exe',
'deep-vaulted.exe',
'deepmouthed.nls',
'deermeat.fly',
'avidemux.mov',
'deering.docx',
'deep-thinking.doc',
'deep-sided.fly',
'deep-thoughted.ppt',
'deck.lnk',
'departed.lnk',
'deep-six.doc',
'desired.dat',
'avsvideoeditor.m3u',
'deep-sunken.exe',
'depart.dat',
'deprive.dat',
'descend.dat',
'deerbrook.ppt',
'deserted.exe',
'defy.dat',
'demand.dat',
'declare.dat',
'deep-grown.exe',
'deep-musing.mp3',
'desolate.dat',
'depended.dat',
'defined.dat',
'demonstrate.dat',
'deerbrook.docx',
'destroyed.dat',
'defeat.dat',
'deceive.dat',
'deserter.dat',
'deepness.ini',
'decidedly.dat',
'decorate.lnk',
'deliverance.lnk',
'depth.lnk',
'definite.lnk',
'deepwater.avi',
'defender.exe',
'deerberry.exe',
'deersking.exe',
'dependent.lnk',
'film.exe',
'dense.lnk',
'decision.txt',
'deep-revolving.fly',
'demanded.txt',
'decisive.dat',
'delightful.lnk',
'despair.dat',
'decoy.dat',
'defense.dat',
'descent.dat',
'desperate.date',
'designer.dat',
'descend.exe',
'desolate.exe',
'delivery.dat',
'delivery.exe',
'deserves.dat',
'decay.lnk',
'derived.lnk',
'deserted.lnk',
'deed.lnk',
'deceive.lnk',
'declared.exe',
'declared.lnk',
'delusion.lnk',
'detachment.exe',
'deploy.lnk',
'deficiency.lnk',
'detachment.lnk',
'mediatv.mov',
'decency.exe',
'videotv.m3u',
'depended.lnk',
'derived.exe',
'desperately.lnk',
'defender.dat',
'decide.lnk',
'departure.lnk',
'deity.lnk',
'decent.lnk',
'demolition.lnk',
'deserter.lnk',
'deceived.lnk',
'designed.lnk',
'deerflies.fly',
'dene.lnk',
'deny.lnk',
'deny.exe',
'delusion.exe',
'deliberate.txt',
'dessert.txt',
'deer.lnk',
'delirium.lnk',
'deserves.lnk',
'smycwtexsedfcwu.wsf',
'depend.lnk',
'defensive.lnk',
'dessert.lnk',
'denote.lnk',
'depart.lnk',
'delicious.lnk',
'demanded.lnk',
'delighted.lnk',
'destitute.lnk',
'decimal.lnk',
'design.lnk',
'desperate.lnk',
'default.lnk',
'destroyer.lnk',
'deceptive.lnk',
'decency.lnk',
'departments.lnk',
'webmedia.m3u',
'tvplaylist.mov',
'destruction.lnk',
'defiance.lnk',
'deputy.lnk',
'planeta.exe',
'deployment.lnk',
'deliver.lnk',
'deliberately.lnk',
'degree.lnk',
'dedicate.lnk',
'defiant.exe',
'deep-versed.nls',
'z4z05jn4.egf.exe',
'deep-green.exe',
'hateful.ico',
'saviour.ico',
'2444.tmp',
'32161.cmd',
'MSRC4Plugin_for_sc.dsm',
'rc4.key',
'UltraVNC.ini',
'deprive.lnk',
'departure.exe',
'SuspiciousFile.test'
)
#endregion end of list
# End of list


# ==================== variable to change for one drive ====================================================
$Drive = "C:\" # <<<<<<<<<<<<<<<<<<<<< You can change the letter for other drive >>>>>>>>>>>>>>>>>>>>
#

#region
$Algorithms = @("MD5","SHA1","SHA256")
# ==========================================================================================================
        Write-Host "<<<<<<<<<<<<<<<<<<<< Scaning drive ${Drive} on ${COMPUTERNAME} >>>>>>>>>>>>>>>>>>>>" -ForegroundColor Cyan

# ==================== Create dir for results and logs =====================================================
$DirPathSF = ${Drive}  + "SuspiciousFile"
        
		if (!(Test-Path -Path ${DirPathSF})){
            Write-Host "create dir ${DirPathSF}" -ForegroundColor Yellow
            New-Item -ItemType Directory -Path ${DirPathSF}
            Write-Host
        }

# ==================== Do not change these variablese ======================================================
$DriveLetter = ${Drive}.Substring(0,1)
$DriveLetter = "Drive" + ${DriveLetter} 

$ResultFile = ${DirPathSF} + "\" + "SuspiciousFileFound" + ${DriveLetter} + ".txt"
$ErrorsFile = ${DirPathSF} + "\" + "ErrorsFile" + ${DriveLetter} + ".txt"

		$GD = Get-Date -Format "dd-MM-yyyy-HH-mm-ss"

        # Rename old file "SuspiciousFileFound${DriveLetter}.txt":
        $ResultFileDestination  = ${ResultFile} + "-" + ${GD} + ".old"
		${TestPathResultFile} = Test-Path -Path ${ResultFile}

			if (${TestPathResultFile} -like $true){
			   Move-Item -Path ${ResultFile} -Destination $ResultFileDestination  -Force
			}

        # Rename old file "ErrorsFile${DriveLetter}.txt":
        $ErrorsFileDestination = ${ErrorsFile} + "-" + ${GD} + ".old"
		${TestPathErrorsFile} = Test-Path -Path ${ErrorsFile}

			if (${TestPathErrorsFile} -like $true){
			   Move-Item -Path ${ErrorsFile} -Destination $ErrorsFileDestination -Force
			}

# ==================== Create a test file  =================================================================
# this created file is at the end of the list
		$TestFilePath = ${DirPathSF} + "\" + "SuspiciousFile.test"
        
			if (!(Test-Path -Path ${TestFilePath})){
				Write-Host "create file $TestFilePath" -ForegroundColor Yellow
				New-Item -ItemType File -Path ${TestFilePath} -Value "this is not a suspicious file, just a test file"
			}
				Write-Host

# ==================== Sort list objects  ==================================================================
	Write-Host "Sort the list :" -ForegroundColor Green

# Count objects before sorting
    $InitialList = $SuspiciousFiles.Count
    Write-Host "Initial list = ${InitialList} files" -ForegroundColor Yellow
  
# Sorting objects
	$SuspiciousFilesUnique = ${SuspiciousFiles} | Select-Object -Unique
	$ListAfterSorting = ${SuspiciousFilesUnique}.Count
    Write-Host "List after sorting = ${ListAfterSorting} files" -ForegroundColor Yellow
    Write-Host  
	
# For show duplicate objects:
	#Compare-object –referenceobject ${SuspiciousFiles} –differenceobject ${SuspiciousFilesUnique}
	
	

# ==================== Get-ChildItem & Get-FileHash  =======================================================
    $COMPUTERNAME  = $Env:COMPUTERNAME
	$GetDate = Get-Date -Format "dd/MM/yyyy HH:mm:ss"

	Write-Host "${GetDate} - Start the scan :" -ForegroundColor Green

	Write-Output "==============================================================================" > ${ResultFile} # one >
	Write-Output "========== ${GetDate} - Find suspicious files on ${COMPUTERNAME}" >> ${ResultFile}
	Write-Output "==============================================================================" >> ${ResultFile}

	$incre = 0
    foreach (${FileName} in ${SuspiciousFilesUnique}) {

            $GetDate = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
            $Error.Clear()
			
			$incre++
			#Format the number as 4 digits
			$Counter = "{0:0000}" -f $incre
			
            Write-Host "${GetDate} - Find the file ${Counter} : ' ${FileName} '" -ForegroundColor Yellow
            
           $FullName = (Get-ChildItem -Path ${Drive} -Recurse -ErrorVariable ErrorObject -ErrorAction SilentlyContinue | Where-Object {$_.Name -like ${FileName}}).FullName

				if (${Error}.Count -ieq 0 ){
                    Write-Output " ${GetDate} - file number ${Counter} : ${FileName} on $COMPUTERNAME " >> ${ErrorsFile}
                    Write-Output " Without Error" >> ${ErrorsFile}
                    }
                else {
                    Write-Output " ${GetDate} - file number ${Counter} : ${FileName} on $COMPUTERNAME " >> ${ErrorsFile}
				    Write-Output ${ErrorObject}[0] >> ${ErrorsFile}
                    }
					
            # Get-FileHash MD5, SHA1 and SHA256: 
            $FullNameCount = $FullName.Count

                if (${FullNameCount} -cgt 0){

                    foreach ($file in ${FullName}){

                            foreach ($Algorithm in ${Algorithms}){

                                Get-FileHash -Algorithm ${Algorithm} -Path ${file} | Select-Object Path,Algorithm,Hash | Format-List | Write-Output >> ${ResultFile}
                            }
                    }
                }
    }
            Write-Output " ${GetDate} - Total Files Scanned on ${Drive} = ${incre} " >> ${ErrorsFile}

                                         
    # Get the number of locations of found files and divide /3 ("MD5","SHA1","SHA256")
    $ConutFileLocations = (Get-Content ${ResultFile}  | select-string -pattern "MD5","SHA1","SHA256").Count
    $ConutFileLocations = ${ConutFileLocations} /3

    # Result messages
    $GetDate = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    Write-Output "========== ${GetDate} - Total Files Scanned on ${Drive} = ${incre} " >> ${ResultFile}
    Write-Output "========== There are ${ConutFileLocations} suspicious file locations found ======================= " >> ${ResultFile}
  	Write-Output "==============================================================================" >> ${ResultFile}
	Write-Output "========== ${GetDate} -  End suspicious files on ${COMPUTERNAME} " >> ${ResultFile}
	Write-Output "==============================================================================" >> ${ResultFile}


	Write-Host "${GetDate} - Total files searched = ${incre}" -ForegroundColor Yellow
    Write-Host "${GetDate} - There are" -NoNewline -ForegroundColor Yellow
    Write-Host " ${ConutFileLocations} " -NoNewline -ForegroundColor Red
    Write-Host "suspicious file locations found on ${COMPUTERNAME}" -ForegroundColor Yellow
    Write-Host "${GetDate} - End the scan . find results in ${ResultFile}" -ForegroundColor Green
    Write-Host


#endregion
} 
# End Invoke-Command
    ${GetDate} = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    Write-Host "${GetDate} Warning: do not close this window, remote job is running !" -ForegroundColor DarkYellow
}
#endregion ==================== End Remote jobs run =======================================================
# End Remote jobs run ($Server in ${ServresList})


	Write-Host
	Write-Host "<<<<<<<<<<<<<<<<<<<< Remote jobs results >>>>>>>>>>>>>>>>>>>>" -ForegroundColor Cyan
    Write-Host
#region ==================== Remote jobs results ===========================================================

    $JobName = "FindSuspiciousFiles"
    
    $ScannedDrive = "C:\" # You can change the letter for other drive
    $DirPathSF = $ScannedDrive  + "SuspiciousFile"
    $OutputFileJobs = $DirPathSF + "\" + "OutputFileJob.txt"

    

    $JobsIds = Get-Job | Where-Object {$_.Name -like ${JobName}} | Select-Object Id
    $JobsIds | Wait-Job

    $OutPut = @()
        foreach ($JobId in $JobsIds){
            Start-Sleep 1
            $OutPut += $JobId | Receive-Job | Select-Object LastWriteTime,PSComputerName,Name,Mode | Format-Table
            $JobId | Remove-Job
        }

    $OutPut | Out-File $OutputFileJobs
    

    ${GetDate} = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    Write-Host
    Write-Host "                *** ${GetDate} End of execution of remote jobs ***" -ForegroundColor Green

#endregion

# ========================== End of script =================================================================

