<#
Script Name 	:07.FindSuspiciousFilesByHashValueOneDriveRemoteServers.ps1
Description		:PowerShell script that scans a drive to find malicious files their hashes are listed in the list below.
                :When a suspicious file is found, it will be noted with the hash in a result file "Drive:\SuspiciousFile\SuspiciousFileFoundByHashValueDrive[X].txt".
				:You can receive the latest malware hashes daily. You must register on a cybersecurity solution site, example: AlienVault OTX (SIEM Open source) (https://otx.alienvault.com/). 
Model			:One drive - Running on remote machine (Remote-Job)-  (Windows Server and Windows Workstation).
PSVersion	    :Windows PowerShell 4.0 and later, PowerShell Core.
Author			:Driss BENELKAID
Mail			:benelkaid.driss@outlook.fr - benelkaid.d@gmail.com
Version			:2.1
Created			:14/03/2022 - 16h00
Last modified	:04/12/2024 - 15h00
Shared script	:https://github.com/DBENELKAID/find-malicious-files.git
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
# You can add or change other hash to this list:
# *** The first hash in the following list (SHA256) of the PNG image file, it was used on 03/25/2022 with steganography to deploy the 'Serpent' Backdoor on organizations in France.***
# https://otx.alienvault.com/indicator/url/https:%2F%2Fwww.fhccu.com%2Fimages%2F7.jpg

$HashList = @(
'abbd8c1109e45ec06202ce21064a876039305a86bff2e11781cbef80f2b82997'
)
#endregion end of list
# End of list


$Algorithms = @('SHA256') # you can use only one algorithm if your hash list is of the same hash type.
#$Algorithms = @('MD5','SHA1','SHA256') 
#$Algorithms = @('MACTripleDES','MD5','RIPEMD160','SHA1','SHA256','SHA384','SHA512') # Algorithms supported by Windows Powreshell 5.1


# ==================== variable to change for one drive ====================================================
$Drive = "C:\" # <<<<<<<<<<<<<<<<<<<<< You can change the letter for other drive >>>>>>>>>>>>>>>>>>>>
#
#region Scaning
# ==========================================================================================================
        Write-Host "<<<<<<<<<<<<<<<<<<<< Scaning drive ${Drive} >>>>>>>>>>>>>>>>>>>>" -ForegroundColor Cyan

# ==================== Create dir for results and logs =====================================================
$DirPathSF = ${Drive}  + "SuspiciousFile"
        
		if (!(Test-Path -Path ${DirPathSF})){
            Write-Host "create dir ${DirPathSF}" -ForegroundColor Yellow
            New-Item -ItemType Directory -Path ${DirPathSF}
            Write-Host
        }

# ==================== Do not change these variablese ======================================================
$DriveLetter = ${Drive}.Substring(0,1)
$Pattern = ${Drive}.Substring(0,2)
$DriveLetter = "Drive" + ${DriveLetter} 

$ResultFile = ${DirPathSF} + "\" + "SuspiciousFileFoundByHashValue" + ${DriveLetter} + ".txt"
$ErrorsFile = ${DirPathSF} + "\" + "ErrorsFileByHashValue" + ${DriveLetter} + ".txt"
	
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

# ==================== Sort list objects  ==================================================================
	Write-Host "Sort the list :" -ForegroundColor Green

# Count objects before sorting
    $InitialList = $HashList.Count
    Write-Host "Initial list = ${InitialList} hash" -ForegroundColor Yellow
  
# Sorting objects
	$HashListUnique = ${HashList} | Select-Object -Unique
	$ListAfterSorting = ${HashListUnique}.Count
    Write-Host "List after sorting = ${ListAfterSorting} hash" -ForegroundColor Yellow
    Write-Host  
	
# For show duplicate objects:
	#Compare-object –referenceobject ${HashList} –differenceobject ${HashListUnique}
	
	

# ==================== Get-ChildItem & Get-FileHash  =======================================================
    $COMPUTERNAME  = $Env:COMPUTERNAME
	$GetDate = Get-Date -Format "dd/MM/yyyy HH:mm:ss"

	Write-Host "${GetDate} - Start the scan :" -ForegroundColor Green

	Write-Output "==============================================================================" > ${ResultFile} # one >
	Write-Output "========== ${GetDate} - Find suspicious files on ${COMPUTERNAME}" >> ${ResultFile}
	Write-Output "==============================================================================" >> ${ResultFile}

    $incre = 0
    foreach ($Hash in $HashListUnique){
    $GetDate = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    $Error.Clear()

    $incre++
	#Format the number as 2 digits
	$Counter = "{0:00}" -f $incre
			
        Write-Host "${GetDate} - Find hash ${Counter} : ' ${Hash} '" -ForegroundColor Yellow

        foreach ($Algorithm in $Algorithms){

            $C = Get-ChildItem ${Drive} -Recurse -ErrorVariable ErrorObjectGci -ErrorAction SilentlyContinue | Get-FileHash -Algorithm $Algorithm -ErrorVariable ErrorObjectGfh -ErrorAction SilentlyContinue | Where-Object {$_.Hash -eq $Hash} | Select-Object Hash,Path | Format-List
            $C | Write-Output >> ${ResultFile}
            Write-Host $C.Path -ForegroundColor Red
            Write-Host
			if (${Error}.Count -ieq 0 ){
				Write-Output " ${GetDate} - Hash number ${Counter} : ${Hash} on $COMPUTERNAME " >> ${ErrorsFile}
				Write-Output " Search completed without error" >> ${ErrorsFile}
			}
			else {
				Write-Output " ${GetDate} - Hash number ${Counter} : ${Hash} on $COMPUTERNAME " >> ${ErrorsFile}
				Write-Output ${ErrorObjectGci}[0] >> ${ErrorsFile}
                Write-Output ${ErrorObjectGfh}[0] >> ${ErrorsFile}
			}

        }
    }
            Write-Output " ${GetDate} - Total Hash searched on ${Drive} = ${incre} " >> ${ErrorsFile}


    
    # Get the number of files found: 
    $Paths = Get-Content -Path ${ResultFile} | Select-String -AllMatches -Pattern ${Pattern}
    $PathsCount = $Paths.Count


    # Result messages
    $GetDate = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    Write-Output "========== ${GetDate} - Total Hash searched on ${Drive} = ${incre} " >> ${ResultFile}
    Write-Output "========== There are ${PathsCount} suspicious file found ================================= " >> ${ResultFile}
  	Write-Output "==============================================================================" >> ${ResultFile}
	Write-Output "========== ${GetDate} -  End suspicious files on ${COMPUTERNAME} " >> ${ResultFile}
	Write-Output "==============================================================================" >> ${ResultFile}


	Write-Host "${GetDate} - Total Hash searched = ${incre}" -ForegroundColor Yellow
    Write-Host "${GetDate} - There are" -NoNewline -ForegroundColor Yellow
    Write-Host " ${PathsCount} " -NoNewline -ForegroundColor Red
    Write-Host "suspicious file found on the drive ${Pattern} - ${COMPUTERNAME}" -ForegroundColor Yellow
    Write-Host "${GetDate} - End the scan . find results in ${ResultFile}" -ForegroundColor Green
    Write-Host


#endregion Scaning
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

