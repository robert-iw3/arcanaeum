-- =============================================
-- Script 1: Configure Linked Server on Consolidated Instance
-- Run on the dedicated ConsolidatedEventsENS SQL Server instance
-- Enhanced: TRY/CATCH, detailed logging
-- =============================================

USE master;
GO

DECLARE
    @LinkedServerName   NVARCHAR(128) = N'EPO_PRODUCTION',
    @ProductionServer   NVARCHAR(128) = N'production-sql-server.fqdn',  -- Replace with actual
    @RemoteUser         NVARCHAR(128) = N'ens_readonly_user',
    @RemotePassword     NVARCHAR(128) = N'StrongPassword123!';          -- Replace securely

BEGIN TRY
    IF EXISTS (SELECT 1 FROM sys.servers WHERE name = @LinkedServerName)
    BEGIN
        PRINT N'Dropping existing linked server...';
        EXEC sp_dropserver @server = @LinkedServerName, @droplogins = 'droplogins';
    END

    PRINT N'Creating linked server...';
    EXEC sp_addlinkedserver
        @server = @LinkedServerName,
        @srvproduct = N'SQL Server',
        @provider = N'SQLNCLI',
        @datasrc = @ProductionServer;

    PRINT N'Adding login mapping...';
    EXEC sp_addlinkedsrvlogin
        @rmtsrvname = @LinkedServerName,
        @useself = N'False',
        @locallogin = NULL,
        @rmtuser = @RemoteUser,
        @rmtpassword = @RemotePassword;

    PRINT N'Testing connection...';
    EXEC sp_testlinkedserver @LinkedServerName;

    PRINT N'Linked server configured successfully.';
END TRY
BEGIN CATCH
    DECLARE @ErrorMsg NVARCHAR(4000) = ERROR_MESSAGE();
    PRINT N'Linked server setup failed: ' + @ErrorMsg;
    THROW;
END CATCH
GO