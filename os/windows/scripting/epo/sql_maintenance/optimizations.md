### ePO Database Optimization Strategies

**Trellix + Microsoft best practices for 5.10.0:**

| Strategy                     | Command / Setting                              | Benefit |
|-----------------------------|------------------------------------------------|---------|
| **Recovery Model**          | `ALTER DATABASE ePO SET RECOVERY FULL`        | Required for HA |
| **Instant File Init**       | Already enabled in our SQL script             | Faster growth |
| **TempDB**                  | 1 file per core (max 8), 8 GB initial size    | Eliminates contention |
| **Max Server Memory**       | Leave at 0 (dynamic) or set to 75% of RAM     | Prevents OS paging |
| **Index Maintenance**       | Weekly `REORGANIZE` + monthly `REBUILD`       | Keeps queries fast |
| **Statistics Update**       | `UPDATE STATISTICS` nightly                    | Query optimizer accuracy |
| **Partitioning**            | Partition `Events` and `AuditLog` tables      | For >150k nodes |

**Automated weekly maintenance job (add to SQL script):**
```sql
EXEC sp_configure 'max server memory (MB)', 0; RECONFIGURE;
-- Weekly index maintenance
EXEC msdb.dbo.sp_start_job @job_name = 'ePO-IndexMaintenance';
```

**See the Trellix ePO Database Maintenance sql script as well!**