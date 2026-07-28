function Get-DsmHardwareIdFromInstanceId {
    <#
    .SYNOPSIS
        Derives a hardware ID root from a PnP device instance ID (e.g. USB\VID_046D&PID_C52B).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $InstanceId
    )

    if ([string]::IsNullOrWhiteSpace($InstanceId)) {
        return $null
    }

    $parts = $InstanceId -split '\\'
    if ($parts.Count -ge 2) {
        return ($parts[0] + '\' + $parts[1])
    }

    return $InstanceId
}

function ConvertFrom-PnPUtilDeviceCsv {
    <#
    .SYNOPSIS
        Parses pnputil /enum-devices /drivers /format csv rows.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]] $InputObject
    )

    begin {
        $rows = [System.Collections.Generic.List[object]]::new()
        $header = $null
    }

    process {
        foreach ($line in $InputObject) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            if (-not $header) {
                $header = $line
                continue
            }

            $cols = $line -split ',(?=(?:[^"]*"[^"]*")*[^"]*$)'
            $rows.Add($cols)
        }
    }

    end {
        if (-not $header) { return (Write-DsmObjectArray) }

        $headerFields = $header -split ',(?=(?:[^"]*"[^"]*")*[^"]*$)' |
            ForEach-Object { $_.Trim('"').Trim() }

        $devices = [System.Collections.Generic.List[object]]::new()

        foreach ($cols in $rows) {
            $dict = [ordered]@{}
            for ($i = 0; $i -lt [Math]::Min($headerFields.Count, $cols.Count); $i++) {
                $key = $headerFields[$i]
                $value = $cols[$i].Trim('"').Trim()
                # pnputil CSV repeats DriverName; keep the first non-empty value per key.
                if (-not $dict.Contains($key) -or [string]::IsNullOrWhiteSpace($dict[$key])) {
                    $dict[$key] = $value
                }
            }

            $instanceId = $dict['Device Instance ID']
            if (-not $instanceId) { $instanceId = $dict['Instance ID'] }
            if (-not $instanceId) { $instanceId = $dict['Device Instance Id'] }
            if (-not $instanceId) { $instanceId = $dict['InstanceId'] }

            $description = $dict['Device Description']
            if (-not $description) { $description = $dict['Description'] }
            if (-not $description) { $description = $dict['DeviceDescription'] }

            $driverName = $dict['Driver Name']
            if (-not $driverName) { $driverName = $dict['DriverName'] }
            if (-not $driverName) { $driverName = $dict['Published Name'] }

            if (-not $driverName -and $instanceId) {
                foreach ($value in $dict.Values) {
                    if ($value -match '^(oem\d+\.inf)$') {
                        $driverName = $Matches[1]
                        break
                    }
                }
            }

            if (-not $driverName) { continue }

            $hwRoot = $null
            if (-not [string]::IsNullOrWhiteSpace($instanceId)) {
                $hwRoot = Get-DsmHardwareIdFromInstanceId -InstanceId $instanceId
            }
            $hardwareIds = [System.Collections.Generic.List[string]]::new()
            if (-not [string]::IsNullOrWhiteSpace($instanceId)) {
                $hardwareIds.Add($instanceId) | Out-Null
            }
            if ($hwRoot -and $hwRoot -ne $instanceId) {
                $hardwareIds.Add($hwRoot) | Out-Null
            }

            $devices.Add([pscustomobject]@{
                    InstanceId    = $instanceId
                    Description   = $description
                    DriverName    = $driverName
                    HardwareIds   = @($hardwareIds | Select-Object -Unique)
                    HardwareIdRoot = $hwRoot
                })
        }

        return (Write-DsmObjectArray -InputObject $devices)
    }
}

function Get-DsmDeviceDriverCorrelation {
    <#
    .SYNOPSIS
        Maps published driver INF names to installed devices (connected vs disconnected).
    #>
    [CmdletBinding()]
    param()

    $tempAll = [System.IO.Path]::GetTempFileName()
    $tempConnected = [System.IO.Path]::GetTempFileName()

    try {
        $allLines = Invoke-DsmPnPUtil -ArgumentList @(
            '/enum-devices', '/drivers', '/format', 'csv'
        ) -OutputFile $tempAll

        $connectedLines = Invoke-DsmPnPUtil -ArgumentList @(
            '/enum-devices', '/connected', '/drivers', '/format', 'csv'
        ) -OutputFile $tempConnected

        $allDevices = ConvertFrom-PnPUtilDeviceCsv -InputObject $allLines
        $connectedDevices = ConvertFrom-PnPUtilDeviceCsv -InputObject $connectedLines

        $connectedInstances = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        foreach ($d in $connectedDevices) {
            if ($d.InstanceId) { [void]$connectedInstances.Add($d.InstanceId) }
        }

        $byPublished = @{}

        foreach ($device in $allDevices) {
            $published = $device.DriverName
            if ($published -notmatch '^(oem\d+\.inf)$') { continue }

            if (-not $byPublished.ContainsKey($published)) {
                $byPublished[$published] = @{
                    Devices                       = [System.Collections.Generic.List[string]]::new()
                    InstanceIds                   = [System.Collections.Generic.List[string]]::new()
                    HardwareIds                   = [System.Collections.Generic.HashSet[string]]::new(
                        [StringComparer]::OrdinalIgnoreCase
                    )
                    HardwareIdRoots               = [System.Collections.Generic.HashSet[string]]::new(
                        [StringComparer]::OrdinalIgnoreCase
                    )
                    ConnectedDeviceCount          = 0
                    DisconnectedInstalledCount    = 0
                }
            }

            $entry = $byPublished[$published]
            if ($device.Description) {
                $entry.Devices.Add($device.Description) | Out-Null
            }

            if ($device.InstanceId) {
                $entry.InstanceIds.Add($device.InstanceId) | Out-Null
            }

            foreach ($hid in $device.HardwareIds) {
                [void]$entry.HardwareIds.Add($hid)
            }

            if ($device.HardwareIdRoot) {
                [void]$entry.HardwareIdRoots.Add($device.HardwareIdRoot)
            }

            if ($device.InstanceId -and $connectedInstances.Contains($device.InstanceId)) {
                $entry.ConnectedDeviceCount++
            }
            else {
                $entry.DisconnectedInstalledCount++
            }
        }

        $result = @{}
        foreach ($key in $byPublished.Keys) {
            $e = $byPublished[$key]
            $deviceList = @($e.Devices | Select-Object -Unique)
            $instanceList = @($e.InstanceIds | Select-Object -Unique)
            $hwList = @($e.HardwareIds)
            $hwRoots = @($e.HardwareIdRoots)

            $association = 'NeverAssociated'
            if ($e.ConnectedDeviceCount -gt 0) {
                $association = 'Connected'
            }
            elseif ($e.DisconnectedInstalledCount -gt 0) {
                $association = 'DisconnectedInstalled'
            }

            $result[$key] = [pscustomobject]@{
                PublishedName                  = $key
                Devices                        = $deviceList
                DeviceInstanceIds              = $instanceList
                HardwareIds                    = $hwList
                HardwareIdRoots                = $hwRoots
                ConnectedDeviceCount           = $e.ConnectedDeviceCount
                DisconnectedInstalledDeviceCount = $e.DisconnectedInstalledCount
                DeviceCount                    = $deviceList.Count
                DeviceAssociation              = $association
            }
        }

        return $result
    }
    catch {
        Write-Warning "Device driver correlation failed: $($_.Exception.Message)"
        return $null
    }
    finally {
        Remove-Item -LiteralPath $tempAll, $tempConnected -Force -WhatIf:$false -ErrorAction SilentlyContinue
    }
}

function Add-DsmDeviceCorrelationToInventory {
    <#
    .SYNOPSIS
        Enriches DsmDriverPackage objects with HWIDs and three-bucket association state.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject[]] $Inventory,

        [hashtable] $Correlation
    )

    if (-not $PSBoundParameters.ContainsKey('Correlation')) {
        $Correlation = Get-DsmDeviceDriverCorrelation
    }

    $failed = ($null -eq $Correlation)

    foreach ($pkg in $Inventory) {
        if ($failed) {
            $pkg | Add-Member -NotePropertyName HardwareIds -NotePropertyValue @() -Force
            $pkg | Add-Member -NotePropertyName HardwareIdRoots -NotePropertyValue @() -Force
            $pkg | Add-Member -NotePropertyName DeviceInstanceIds -NotePropertyValue @() -Force
            $pkg | Add-Member -NotePropertyName ConnectedDeviceCount -NotePropertyValue 0 -Force
            $pkg | Add-Member -NotePropertyName DisconnectedInstalledDeviceCount -NotePropertyValue 0 -Force
            $pkg | Add-Member -NotePropertyName DeviceAssociation -NotePropertyValue 'Unknown' -Force
            $pkg | Add-Member -NotePropertyName InUse -NotePropertyValue $false -Force
            if (-not $pkg.PSObject.Properties['DeviceCount']) {
                $pkg | Add-Member -NotePropertyName DeviceCount -NotePropertyValue 0 -Force
            }
            continue
        }

        $match = $Correlation[$pkg.PublishedName]

        if ($match) {
            $pkg | Add-Member -NotePropertyName Devices -NotePropertyValue $match.Devices -Force
            $pkg | Add-Member -NotePropertyName DeviceInstanceIds -NotePropertyValue $match.DeviceInstanceIds -Force
            $pkg | Add-Member -NotePropertyName HardwareIds -NotePropertyValue $match.HardwareIds -Force
            $pkg | Add-Member -NotePropertyName HardwareIdRoots -NotePropertyValue $match.HardwareIdRoots -Force
            $pkg | Add-Member -NotePropertyName ConnectedDeviceCount -NotePropertyValue $match.ConnectedDeviceCount -Force
            $pkg | Add-Member -NotePropertyName DisconnectedInstalledDeviceCount -NotePropertyValue $match.DisconnectedInstalledDeviceCount -Force
            $pkg | Add-Member -NotePropertyName DeviceCount -NotePropertyValue $match.DeviceCount -Force
            $pkg | Add-Member -NotePropertyName DeviceAssociation -NotePropertyValue $match.DeviceAssociation -Force
            $pkg | Add-Member -NotePropertyName InUse -NotePropertyValue ($match.DeviceAssociation -eq 'Connected') -Force
        }
        else {
            $pkg | Add-Member -NotePropertyName HardwareIds -NotePropertyValue @() -Force
            $pkg | Add-Member -NotePropertyName HardwareIdRoots -NotePropertyValue @() -Force
            $pkg | Add-Member -NotePropertyName DeviceInstanceIds -NotePropertyValue @() -Force
            $pkg | Add-Member -NotePropertyName ConnectedDeviceCount -NotePropertyValue 0 -Force
            $pkg | Add-Member -NotePropertyName DisconnectedInstalledDeviceCount -NotePropertyValue 0 -Force
            $pkg | Add-Member -NotePropertyName DeviceAssociation -NotePropertyValue 'NeverAssociated' -Force
            $pkg | Add-Member -NotePropertyName InUse -NotePropertyValue $false -Force
            if (-not $pkg.PSObject.Properties['DeviceCount']) {
                $pkg | Add-Member -NotePropertyName DeviceCount -NotePropertyValue 0 -Force
            }
        }
    }

    return (Write-DsmObjectArray -InputObject $Inventory)
}

function Update-DsmPackageDeletionEligibility {
    <#
    .SYNOPSIS
        Re-applies device correlation for one package immediately before deletion.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject] $Package
    )

    $correlation = Get-DsmDeviceDriverCorrelation
    if ($null -eq $correlation) {
        $Package | Add-Member -NotePropertyName DeviceAssociation -NotePropertyValue 'Unknown' -Force
        $Package | Add-Member -NotePropertyName InUse -NotePropertyValue $false -Force
        $Package | Add-Member -NotePropertyName ConnectedDeviceCount -NotePropertyValue 0 -Force
        $Package | Add-Member -NotePropertyName DisconnectedInstalledDeviceCount -NotePropertyValue 0 -Force
        return $Package
    }

    $match = $correlation[$Package.PublishedName]
    if ($match) {
        $Package | Add-Member -NotePropertyName DeviceAssociation -NotePropertyValue $match.DeviceAssociation -Force
        $Package | Add-Member -NotePropertyName InUse -NotePropertyValue ($match.DeviceAssociation -eq 'Connected') -Force
        $Package | Add-Member -NotePropertyName ConnectedDeviceCount -NotePropertyValue $match.ConnectedDeviceCount -Force
        $Package | Add-Member -NotePropertyName DisconnectedInstalledDeviceCount -NotePropertyValue $match.DisconnectedInstalledDeviceCount -Force
    }
    else {
        $Package | Add-Member -NotePropertyName DeviceAssociation -NotePropertyValue 'NeverAssociated' -Force
        $Package | Add-Member -NotePropertyName InUse -NotePropertyValue $false -Force
        $Package | Add-Member -NotePropertyName ConnectedDeviceCount -NotePropertyValue 0 -Force
        $Package | Add-Member -NotePropertyName DisconnectedInstalledDeviceCount -NotePropertyValue 0 -Force
    }

    return $Package
}
