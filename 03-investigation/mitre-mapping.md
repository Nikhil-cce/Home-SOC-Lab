# MITRE ATT&CK mapping

## Observed in the lab

| Tactic | Technique | ID | Evidence | Detection | Data source |
|---|---|---|---|---|---|
| Credential Access (TA0006) | Brute Force: Password Guessing | T1110.001 | 5 failed network logons (4625) against `SocLab` from 192.168.0.108 in 23 seconds | SOC - Brute force login attempts | Windows Security log, logon failures |
| Execution (TA0002) | Command and Scripting Interpreter: PowerShell | T1059.001 | `powershell.exe -Command ...` started by a user from an interactive session | SOC - Suspicious Powershell Execution | Sysmon Event 1, process creation and command line |
| Defense Evasion (TA0005) | Hide Artifacts: Hidden Window | T1564.003 | `-WindowStyle Hidden` in the command line | SOC - Suspicious Powershell Execution | Sysmon Event 1, command line |

## Why I picked T1110.001 and not another sub technique

| Sub technique | Pattern | Fit |
|---|---|---|
| T1110.001 Password Guessing | Many guesses against one account | Yes. One account, repeated guesses |
| T1110.003 Password Spraying | One password against many accounts | No. Only `SocLab` was targeted |
| T1110.004 Credential Stuffing | Leaked username and password pairs | No evidence of that |

## Covered by the PowerShell rule but not tested

The regex looks for these patterns too. I did not run them in the lab, so these are coverage notes and not findings.

| Pattern | Related technique |
|---|---|
| `-encodedcommand`, `-enc` | T1027.010 Obfuscated Files or Information: Command Obfuscation |
| `-executionpolicy bypass` | T1059.001 PowerShell |
| `downloadstring` | T1105 Ingress Tool Transfer, T1059.001 |
| `invoke-expression` | T1059.001 |

## Tactics, techniques and procedures

| | Brute force | PowerShell |
|---|---|---|
| Tactic (the goal) | Credential Access: get a valid password | Execution and Defense Evasion: run code without being noticed |
| Technique (the method) | Password guessing, T1110.001 | PowerShell, T1059.001, with a hidden window, T1564.003 |
| Procedure (what exactly happened here) | Repeated wrong passwords for `SocLab` over the network from Kali, one every 5 to 7 seconds | `powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Output-LAB-TEST"` started from an interactive PowerShell by `SOC_Analyst` |

## Not covered

What the lab does not detect yet: a successful logon after the guessing (T1078 Valid Accounts), what the PowerShell process does after it starts (network connections, child processes), persistence and lateral movement.
