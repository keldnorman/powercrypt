# Run cmd -> Powershell and paste this in 
#----------------------------
# CRYPTER:
#----------------------------
using namespace System.Security.Cryptography
function enc { [CmdletBinding()]  [OutputType([string])]
 Param ([Parameter(Mandatory = $true)][String]$Key,[Parameter(Mandatory = $true)][String]$Text)  
 $sha = New-Object SHA256Managed
 $aes = New-Object AesManaged
 $aes.Mode = [CipherMode]::CBC
 $aes.Padding = [PaddingMode]::Zeros
 $aes.BlockSize = 128
 $aes.KeySize = 256
 $aes.Key = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))
 $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
 $crypt = $aes.CreateEncryptor()
 $encbytes = $crypt.TransformFinalBlock($bytes,0,$bytes.Length)
 $encbytes = $aes.IV + $encbytes
 $aes.Dispose()
 $sha.Dispose()
 return [System.Convert]::ToBase64String($encbytes)
 }
enc -Key "TheCodeIs16Chars" -Text "ExfiltratingSecrets"
#----------------------------
# DE-CRYPTER:
#----------------------------
using namespace System.Security.Cryptography
function dec { [CmdletBinding()]  [OutputType([string])]
 Param ([Parameter(Mandatory = $true)][String]$Key,[Parameter(Mandatory = $true)][String]$Text)  
 $sha = New-Object SHA256Managed
 $aes = New-Object AesManaged
 $aes.Mode = [CipherMode]::CBC
 $aes.Padding = [PaddingMode]::Zeros
 $aes.BlockSize = 128
 $aes.KeySize = 256
 $aes.Key = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))
 $encbytes = [System.Convert]::FromBase64String($Text)
 $aes.IV = $encbytes[0..15]
 $decryp = $aes.CreateDecryptor()
 $bytes = $decryp.TransformFinalBlock($encbytes, 16, $encbytes.Length - 16)
 $aes.Dispose()
 return [System.Text.Encoding]::UTF8.GetString($bytes).Trim([char]0)
}
dec -Key "TheCodeIs16Chars" -Text 'pEcpfIc/3F/ZSB8cMX4G1ZbBegL1qd7dcs3vIbwyF+Ha3tA+cEyqL3I9U3dfWXHC'
