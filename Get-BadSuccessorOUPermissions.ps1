function Get-BadSuccessorOUPermissions {
    <#
    .SYNOPSIS
        Lists every principal that can perform a BadSuccessor attack and the OUs where it holds the required permissions.

    .DESCRIPTION
        Scans all Organizational Units (OUs) for Access Control Entries (ACEs) granting permissions that could allow creation of a delegated Managed Service Account (dMSA),
        enabling a potential BadSuccessor privilege escalation attack.

        Built-in privileged identities (e.g., Domain Admins, Administrators, SYSTEM, Enterprise Admins) are excluded from results. 
        This script does not evaluate DENY ACEs and therefore, some false positives may occur.

        Note: We do not expand group membership and the permissions list used may not be exhaustive. Indirect rights such as WriteDACL on the OU are considered.
    #>

    [CmdletBinding()]
    param ()

    # Cache for IsExcludedSID to reduce network calls
    $SidCache = @{}

    function Test-IsExcludedSID {
        Param ([string]$IdentityReference)

        if ($SidCache.ContainsKey($IdentityReference)) {
            return $SidCache[$IdentityReference]      # instant hit
        }

        try {
            if ($IdentityReference -match '^S-\d-\d+(-\d+)+$') {
                $sid = $IdentityReference
            } else {
                $sid = (New-Object System.Security.Principal.NTAccount($IdentityReference)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            }
        } catch {
            Write-Verbose "Failed to translate $IdentityReference to SID: $_"
            $SidCache[$IdentityReference] = $false
            return $false
        }
        
        # Check excluded SID list and Enterprise Admins (RID 519)
        if (($sid -and ($excludedSids -contains $sid -or $sid.EndsWith("-519")))) {
            return $true
        }

        $isExcluded = ($sid -and ($excludedSids -contains $sid -or $sid.EndsWith('-519')))
        $SidCache[$IdentityReference] = $isExcluded   # remember result
        return $isExcluded
    }
    
    $domainSID = (Get-ADDomain).DomainSID.Value
    $excludedSids = @(
        "$domainSID-512",       # Domain Admins
        "S-1-5-32-544",         # Builtin Administrators
        "S-1-5-18"              # Local SYSTEM
    )    

    # Setup the specific rights we look for, and on which kind of objects - add more attributes' guids as needed
    $relevantObjectTypes = @{"00000000-0000-0000-0000-000000000000"="All Objects";
                             "0feb936f-47b3-49f2-9386-1dedc2c23765"="msDS-DelegatedManagedServiceAccount";}

    # This could be modified to also get objects with indirect access, for example: $relevantRights = "CreateChild|WriteDACL"
    $relevantRights = "CreateChild|GenericAll|WriteDACL|WriteOwner"

    # This will hold the output - every principal that has the required permissions and is not excluded, and on which OUs
    $allowedIdentities = @{}

    $allOUs = Get-ADOrganizationalUnit -Filter * -Properties ntSecurityDescriptor | Select-Object DistinguishedName, ntSecurityDescriptor

    foreach ($ou in $allOUs) {     
        foreach ($ace in $ou.ntSecurityDescriptor.Access) {
            if ($ace.AccessControlType -ne "Allow") {
                continue
            }
            if ($ace.PropagationFlags -eq "InheritOnly") { 
                continue
            }
            if ($ace.ActiveDirectoryRights -notmatch $relevantRights) {
                continue
            }
            if (-not $relevantObjectTypes.ContainsKey($ace.ObjectType.Guid)) {
                continue
            }            

            $identity = $ace.IdentityReference.Value
            if (Test-IsExcludedSID $identity) { 
                continue 
            }

            if (-not $allowedIdentities.ContainsKey($identity)) {
                $allowedIdentities[$identity] = [System.Collections.Generic.List[string]]::new()
            }
            $allowedIdentities[$identity].Add($ou.DistinguishedName)
        }

        # Check the owner
        $owner = $ou.ntSecurityDescriptor.Owner

        if (-not (Test-IsExcludedSID $owner)) {
            if (-not $allowedIdentities.ContainsKey($owner)) {
                $allowedIdentities[$owner] = [System.Collections.Generic.List[string]]::new()
            }
            $allowedIdentities[$owner].Add($ou.DistinguishedName)
        }
    }

    foreach ($id in $allowedIdentities.Keys) {
        [PSCustomObject]@{
            Identity = $id
            OUs      = $allowedIdentities[$id].ToArray()
        }
    }
}

# Auto-run if script is executed directly
if ($MyInvocation.InvocationName -ne '.') {
    Get-BadSuccessorOUPermissions @PSBoundParameters
}
