-- =============================================
-- DATABASE STIG FIXES FOR ALL USER DATABASES
-- =============================================

DECLARE @SQL nvarchar(max) = '';

SELECT @SQL = @SQL + '
ALTER DATABASE [' + name + '] SET TRUSTWORTHY OFF;
ALTER DATABASE [' + name + '] SET RECOVERY FULL WITH NO_WAIT;
ALTER AUTHORIZATION ON DATABASE::[' + name + '] TO [dbo];
PRINT ''Fixed: ' + name + ''';
'
FROM sys.databases
WHERE database_id > 4 AND state = 0;

EXEC sp_executesql @SQL;
GO