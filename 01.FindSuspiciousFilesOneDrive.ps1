<#
Script Name 	:01.FindSuspiciousFilesOneDrive.ps1
Description		:PowerShell script that scans a drive to find malware files listed in the list below.
                :and when a suspicious file is found, it will be noted with the "MD5", SHA1 and SHA256 in a result file "Drive\:SuspiciousFileFound.txt".
				:the first files listed in this list are recent, some of which were used by russia to attack ukraine in February 23, 2022.
Model			:One drive - Running on local machine (Windows Server and Windows Workstation).
PSVersion	    :Windows PowerShell 4.0 and later, PowerShell Core.
Author			:Driss BENELKAID
Mail			:benelkaid.driss@outlook.fr - benelkaid.d@gmail.com
Version			:2.0
Last modified	:14/03/2022 - 16h00
Shared script	:https://github.com/DBENELKAID/find-malicious-files.git
				:It is allowed to modify this script to improve it and share it in order to mitigate cyberattaques.
#>

#region list
# ==================== Indicators of compromise list =======================================================
# You can add other files to this list
$SuspiciousFiles = @(
'clean.exe',
'cl.exe',
'cl64.dll',
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

        $ErrorsFileDestination = ${ErrorsFile} + "-" + ${GD} + ".old"
		${TestPathErrorsFile} = Test-Path -Path ${ErrorsFile}

			if (${TestPathErrorsFile} -like $true){
			   Move-Item -Path ${ErrorsFile} -Destination $ErrorsFileDestination -Force
			}

# ==================== Create a test file  =================================================================
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
	Compare-object –referenceobject ${SuspiciousFiles} –differenceobject ${SuspiciousFilesUnique}
	
	

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

                            foreach ($Algorithm in $Algorithms){

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

# ========================== End of script =================================================================
