### Advanced SQL IOPS Tuning + SuperAgent Strategies

#### Advanced SQL IOPS Tuning (per Trellix Guide + Microsoft best practices)
1. **Storage layout** (critical for >75k nodes):
   - TempDB → fastest NVMe/SSD (separate LUN)
   - Data files → RAID-10 or Azure Premium SSD
   - Log files → separate LUN, no caching
   - Use **instant file initialization** (already enabled in our script)

2. **PowerShell one-liner to tune IOPS** (run on SQL server):
```powershell
Invoke-Sqlcmd -ServerInstance "localhost" -Query "
    ALTER DATABASE tempdb MODIFY FILE (NAME = 'tempdev', SIZE = 8192MB, FILEGROWTH = 1024MB);
    ALTER DATABASE tempdb MODIFY FILE (NAME = 'templog', SIZE = 4096MB, FILEGROWTH = 512MB);
    EXEC sp_configure 'max server memory (MB)', 0; RECONFIGURE;
"
```

3. **Filegroup & partition strategy** (for 150k+ nodes):
   - Create dedicated filegroup for ePO tables.
   - Enable **trace flag 1118** (uniform extent allocation) – already default in SQL 2022.

#### SuperAgent Deployment Strategies
- **When to use SuperAgents**: Reduce AH load in large branch offices (>500 systems per site).
- **Deployment script** (add to master orchestrator):
```powershell
# Deploy SuperAgent to a group of systems
Invoke-Command -ComputerName $targetComputers -ScriptBlock {
    & "\\epo-server\ePOShare\Agent\Setup.exe" /install=AGENT /silent /force
}
```

**Best practice**:
- Deploy SuperAgents via ePO task → “Deploy Agents”.
- Set SuperAgent policy: **“Use as SuperAgent” = Enabled**.
- AHs only handle SuperAgent → ePO communication (massive IOPS reduction).