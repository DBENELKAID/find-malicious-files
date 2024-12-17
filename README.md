<<<<<<< HEAD
GitHub Link : https://github.com/DBENELKAID/find-malicious-files.git

# In english

# find-malicious-files
PowerShell scripts that allow you to scan Windows systems (Windows servers or Windows Client) to find malicious files.

Description: PowerShell script that analyzes a disk or a lecteur to find malveillants, the caches that are listed in the $HashList in the script
When a suspicious file is found, it will be noted with the hash in a result file "Drive:\SuspiciousFile\NameOfScript[X].txt".
You can receive the latest malware hashes daily. You must register on a cybersecurity solution site, example: AlienVault OTX (SIEM Open source) (https://otx.alienvault.com/). 
Platforme: All drives - Running on locale machine and remote machine (Windows Server and Windows Workstation).

The script must be run as Administrator to be able to scan all drives.



With these scripts there are two methods to find the malicious file:
01 By searching for the name of the known file.
For this first method there are 4 scripts, two to scan a single local machine (a single hard drive or several disks) and two to scan remote machines (a single hard drive or several).
Script Names:
  01.FindSuspiciousFilesOneDrive.ps1
  02.FindSuspiciousFilesAllDrives.ps1
  03.FindSuspiciousFilesRemoteServersOneDrive.ps1
  04.FindSuspiciousFilesRemoteServersAllDrives.ps1

02 By searching for a hash of a known file.
For this second method there are also 4 scripts, two to scan a single local machine (a single hard drive or several disks) and two to scan remote machines (a single hard drive or several).
Script Names:
  05.FindSuspiciousFilesByHashValueOneDrive.ps1
  06.FindSuspiciousFilesByHashValueAllDrive.ps1
  07.FindSuspiciousFilesByHashValueOneDriveRemoteServers.ps1
  08.FindSuspiciousFilesByHashValueAllDriveRemoteServers.ps1
  

# En francais

# trouver des fichiers malveillants
Des scripts PowerShell qui permettent de scanner des systèmes Windows (Windows serveurs ou Windows Client) pour trouver des fichiers malvaillants.

Description: script PowerShell qui analyse un disque dur ou un lecteur pour trouver des fichiers malveillants, leurs hachages sont listé dans la $HashList haut de script.
Lorsqu'un fichier suspect est trouvé, il sera noté avec le hachage dans un fichier de résultats «Drive:\SuspiciousFile\NameOfScript[X].txt».
Vous pouvez recevoir quotidiennement les derniers hachages de malware. Vous devez vous inscrire sur un site de solution de cybersécurité, par exemple: AlienVault OTX (SIEM Open source) (https://otx.alienvault.com/).
Plateforme: tous les lecteurs - Exécution sur une machine locale et une machine distante (Windows Server et Windows Workstation).

Le script doit etre exécuté en tant qu'Administaretur pour pouvoir scanner tous les lecteurs.

Avec ces script il y a deux methodes pour trouver le fichier malvaillant:
01 Par ar la recherche du nom du fichier connu.
Pour cette première méthode il y a 4 scripts, deux pour scanner une seule machine locale (un seule disque dur ou plusieus disques) et deux pour scanner des machines distantes  (un seule disque dur ou plusieus).
Noms des scripts:
  01.FindSuspiciousFilesOneDrive.ps1
  02.FindSuspiciousFilesAllDrives.ps1
  03.FindSuspiciousFilesRemoteServersOneDrive.ps1
  04.FindSuspiciousFilesRemoteServersAllDrives.ps1

02 Par la recheche d'un hash d'un fichier connu.
Pour cette deuxième méthode il y a 4 aussi scripts, deux pour scanner une seule machine locale (un seule disque dur ou plusieus disques) et deux pour scanner des machines distantes  (un seule disque dur ou plusieus).
Noms des scripts:
  05.FindSuspiciousFilesByHashValueOneDrive.ps1
  06.FindSuspiciousFilesByHashValueAllDrive.ps1
  07.FindSuspiciousFilesByHashValueOneDriveRemoteServers.ps1
  08.FindSuspiciousFilesByHashValueAllDriveRemoteServers.ps1
=======
# Fichier expliquant les intruction du projet PowerShell
# modification DC1
>>>>>>> b229bb5551fd983369f248d36476868d66de88c1
