function Get-IISManagementServiceIPRestrictions ($ComputerName)
{
<# 
   Inspired from a posting in forums.IIS.net
   Https://forums.iis.net/t/1221868.aspx?Powershell+to+Configuring+the+Management+Service
   
   Author: Logan "L-Bo" Boydell
   Date: 04/18/2019
   
   Version 1.0 - Initial Release
#>
  # Set error action preference for error handling
  $ErrorActionPreference = 'Stop'

  # Create blank ArrayList
  [System.Collections.ArrayList]$objColl = @()

  # Set useful varialbes
  $path = 'SOFTWARE\Microsoft\WebManagement\Server'
  $name = 'RemoteRestrictions'

  # Try to collect information from the registry
  Try
    {
      # Check to see if we are running this against a local host or remote host
      $check = '.','localhost',$env:COMPUTERNAME
      if($ComputerName -in $check)
        {
          # running against local host
          $regKey = (Get-ItemProperty -Path HKLM:\$path -Name $name).$name
        }
      else
        {
          # running against remote host
          $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
          $regKey = $reg.openSubKey("$path")
        }
      
      # Handle if $RegKey is null
      if($null -eq $regKey)
        {
          Write-Warning -Message "$path not Found"
          break
        }
      # The setting is Base64 encoded so you need to decode to get a byte array, the data is encoded directly into this byte array
      [System.Collections.ArrayList]$regKeyBytes = [System.Convert]::FromBase64String($regKey)

      
      # The first 21 bytes is a header 
      ## byte 12 encodes the global allow/deny 103=Allow, 104=Deny 
      ## bytes 18 to 21 are a 4 byte int which says how many ip address settings are to follow the header
      $header = $regKeyBytes[0..20]

      # Remove header bytes from collection
      $regkeybytes.RemoveRange(0,21)

      # Determine Global Allow/Deny permission for unspecified clients
      $unspecifiedClientPerm = if($header[11] -match 104){'Deny'}Else{'Allow'}
    }
  Catch [UnauthorizedAccessException]
    {
      Write-Warning -Message "Access Denied"
      break
    }
  Catch
    {
      # Return errors
      $_ | Format-List -Force
      break
    }

    do
    {
      # Following the header are 42 byte chunks for each ip address configured (you can define ipv6 ips and these create larger sections which I dont support) 
      # bytes 1 to 4 are a zero based 4 byte int for the index of the ip address, this should increment by 1 for each ip added 
      # bytes 17,19,21 and 23 represent each octet of the IP address 
      # bytes 31,33,35 and 37 represent each octet of the Subnet address 
      # byte 42 encodes the ip allow/deny 103=Allow, 104=Deny       

      # Since IP addresses are 42 byte segments, I chose not to decipher the number of IP addressess from the header. Instead opting to break the $RegKeyBytes
      # variable into 42 byte chunks for processing. 
      if($regKeyBytes.Count -gt 0)
        {
          # Set currentBytes variable
          $currentBytes = $regKeyBytes[0..41]

          # remove "currentBytes" from $RegKeyBytes
          $regKeyBytes.RemoveRange(0,42)

          # Empty ArrayList for building an IP address
          [System.Collections.ArrayList]$ip = @()
          $null = $ip.Add($currentBytes[16])
          $null = $ip.Add($currentBytes[18])
          $null = $ip.Add($currentBytes[20])
          $null = $ip.Add($currentBytes[22])

          [System.Collections.ArrayList]$sm = @()
          $null = $sm.Add($currentBytes[30])
          $null = $sm.Add($currentBytes[32])
          $null = $sm.Add($currentBytes[34])
          $null = $sm.Add($currentBytes[36])

          $null = $objColl.Add(
          [pscustomobject] @{
          'IPAddress/StartRange' = $ip -join '.'
          'SubNetMask/EndRange' = $sm -join '.'
          Permission = if($currentBytes[-1] -eq 104){'Deny'}Else{'Allow'}
          UnSpecifiedClients = $unspecifiedClientPerm}
          )
        } 
    }
    until($regKeyBytes.Count -eq 0)

    if($objColl.Count -gt 0)
      {
        $objColl | Sort-Object -Property {$_.IP -as [version]}
      }
    else{'No data returned'}
}