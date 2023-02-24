# AmsiBypass123

## Description

Obfuscated version of [AmsiOpenSession patch bypass by TheD1rkMtr](https://github.com/TheD1rkMtr/AMSI_patch).

To use it simply do the following:

Attacker Shell:

```powershell
$pid
```

Auxiliary Shell:

```powershell
C:\path\to\AmsiBypass123.exe {pid_of_attacker_shell}
```

Or, alternatively in the same shell:

```powershell
Start-Process -FilePath "C:\path\to\AmsiBypass123.exe" -ArgumentList "$pid"
```

## Proof of Concept

![PoC](https://user-images.githubusercontent.com/46110263/221304917-da306158-ada6-4070-8922-e20593d4004c.png)
