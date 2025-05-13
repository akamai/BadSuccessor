# BadSuccessor

This repository contains tooling related to the **BadSuccessor** attack - a novel Active Directory privilege escalation technique that abuses a vulnerability in a feature introduced in Windows Server 2025.

## What is BadSuccessor?

[BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory) is a privilege escalation vulnerability discovered in Windows Server 2025 that allows attackers to act with the privileges of **any user** in Active Directory, without modifying the target object.

It abuses the **delegated Managed Service Account (dMSA)** feature introduced in Windows Server 2025 and works in the **default configuration**, making it a high-impact, low-complexity attack vector. In 91% of the environments we examined, **non-admin users** had the required permissions to perform the attack.

While Microsoft has acknowledged the issue and will address it in the future, no patch is currently available. 

## Included Tools

### `Get-BadSuccessorOUPermissions.ps1`

This PowerShell script helps defenders identify **which identities have permissions** to create dMSAs in their domain, and **which OUs are affected** - highlighting where the BadSuccessor attack could be executed.
Defenders should review the output and determine whether each identity is highly privileged and appropriately monitored. For any identities that are not, the ACLs of the corresponding OUs should be reviewed and unnecessary permissions removed.

#### Example Output

| Identity              | OU Distinguished Name                          |
|-----------------------|------------------------------------------------|
| CORP\svc_app          | {OU=Apps,DC=corp,DC=local}                       |
| CORP\UserCreators     | {OU=Tier1,OU=IT,DC=corp,DC=local}                |

#### Notes
- Requires only domain read permissions.
- Built-in privileged groups (Domain Admins, Enterprise Admins, etc.) are excluded.
- Does not calculate effective permissions or expand group memberships.

-------

# License 

Copyright 2025 Akamai Technologies Inc.

Akamai follows ethical security research principles and makes this software available so that others can assess and improve the security of their own environments.  
Akamai does not condone malicious use of the software; the user is solely responsible for their conduct.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.