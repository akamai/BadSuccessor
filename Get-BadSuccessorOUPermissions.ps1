function Get-BadSuccessorOUPermissions {
    <#
    .SYNOPSIS
    Get all principals that are allowed to perform BadSuccessor and on which OUs.
    
    .DESCRIPTION
    Scans all Organizational Units (OUs) for Access Control Entries (ACEs) granting permissions that could allow creation of a delegated Managed Service Account (dMSA),
    enabling a potential BadSuccessor privilege escalation attack.

    Built-in privileged identities (e.g., Domain Admins, Administrators, SYSTEM, Enterprise Admins) are excluded from results. 
    This script does not evaluate DENY ACEs and therefore, some false positives may occur.

    Note: We do not expand group membership and the permissions list used may not be exhaustive. Indirect rights such as WriteDACL on the OU are considered.
    #>

    [CmdletBinding()]
    param ()

    function Test-ExcludedSID {
        <#
        .SYNOPSIS
            Returns $true if the identity is in the excluded SIDs list (e.g., Domain Admins).
        #>

        Param (
            $IdentityReference = ""
        )

        try {
            if ($IdentityReference -match '^S-\d-\d+(-\d+)+$') {
                $sid = $IdentityReference
            } else {
                $sid = (New-Object System.Security.Principal.NTAccount($IdentityReference)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            }
        }
        catch {
            Write-Verbose "Failed to translate $IdentityReference to SID: $_"
            return $false
        }
        # Check excluded SID list and Enterprise Admins (RID 519)
        if (($sid -and ($excludedSids -contains $sid -or $sid.EndsWith("-519")))) {
            return $true
        }
        return $false
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

    $allOUs = Get-ADOrganizationalUnit -Filter * -Properties ntSecurityDescriptor | Select-Object DistinguishedName,ntSecurityDescriptor

    foreach ($ou in $allOUs) {     
        foreach ($ou_access in $ou.ntSecurityDescriptor.Access) {
            if ($ou_access.AccessControlType -ne "Allow") {
                continue
            }
            if ($ou_access.ActiveDirectoryRights -notmatch $relevantRights) {
                continue
            }
            if (!$relevantObjectTypes.ContainsKey($ou_access.ObjectType.Guid)) {
                continue
            }            

            # Check if identity is already in the allowedIdentities HT
            if ($allowedIdentities.ContainsKey($ou_access.IdentityReference.Value)) {
                $allowedIdentities[$ou_access.IdentityReference.Value] += ";$($ou.DistinguishedName)"
            }
            else {
                # Identity has the necessary permissions and is not in the allowed identities list yet. Try to find its sid to see if it is excluded
                if (Test-ExcludedSID -IdentityReference $ou_access.IdentityReference.Value) {
                    continue
                }
                $allowedIdentities[$ou_access.IdentityReference.Value] = "$($ou.DistinguishedName)"
            }
        }

        # Check the owner
        $owner = $ou.ntSecurityDescriptor.Owner

        # Check if identity is already in the allowedIdentities HT
        if ($allowedIdentities.ContainsKey($owner)) {
            $allowedIdentities[$owner] += ";$($ou.DistinguishedName)"
        }
        else {
            # This object is OU's owner, try to find its sid to see if it is excluded       
            if (Test-ExcludedSID -IdentityReference $owner) {
                continue
            }
            $allowedIdentities[$owner] = "$($ou.DistinguishedName)"
        }
    }

    # Convert hash table to structured output
    $results = foreach ($id in $allowedIdentities.Keys) {
        [PSCustomObject]@{
            Identity             = $id
            "OU Distinguished Name" = $allowedIdentities[$id] -split ';'
        }
    }

    return $results
}