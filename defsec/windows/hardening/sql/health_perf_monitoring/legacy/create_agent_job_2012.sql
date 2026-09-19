USE msdb;
GO

-- Tunable variables at the top
DECLARE @JobName NVARCHAR(128) = N'SQL_Health_Monitor';  -- Job name
DECLARE @Description NVARCHAR(512) = N'Runs SQL health check script every hour';  -- Job description
DECLARE @Owner NVARCHAR(128) = N'sa';  -- Owner login
DECLARE @StepName NVARCHAR(128) = N'Run Health Check';  -- Step name
DECLARE @Command NVARCHAR(MAX) = N'sqlcmd -S localhost -d master -E -i "C:\Scripts\sql_health_check_2012.sql" -t 300 > "C:\Monitoring\sql_metrics.prom" 2>&1 & type "C:\Monitoring\sql_metrics.prom" >> "C:\Monitoring\health.log"';  -- Command (tune paths/server/auth; note 2012 script path)
DECLARE @ScheduleName NVARCHAR(128) = N'Hourly_Health_Check';  -- Schedule name
DECLARE @FreqSubdayInterval INT = 1;  -- Every X hours

BEGIN TRY
    BEGIN TRANSACTION;

    -- Check if job exists and delete if so (idempotent)
    IF EXISTS (SELECT job_id FROM msdb.dbo.sysjobs_view WHERE name = @JobName)
    BEGIN
        EXEC msdb.dbo.sp_delete_job @job_name = @JobName, @delete_unused_schedule=1;
    END

    -- Create job
    EXEC msdb.dbo.sp_add_job @job_name = @JobName,
        @enabled=1,
        @description=@Description,
        @owner_login_name=@Owner;

    -- Add step (runs sqlcmd, output to prom and append to log)
    EXEC msdb.dbo.sp_add_jobstep @job_name=@JobName, @step_name=@StepName,
        @step_id=1,
        @subsystem=N'CmdExec',
        @command=@Command,
        @on_success_action=1,
        @on_fail_action=2;

    -- Add schedule (hourly)
    EXEC msdb.dbo.sp_add_jobschedule @job_name=@JobName, @name=@ScheduleName,
        @enabled=1,
        @freq_type=4,
        @freq_interval=1,
        @freq_subday_type=8,
        @freq_subday_interval=@FreqSubdayInterval,
        @active_start_time=0;

    -- Add server
    EXEC msdb.dbo.sp_add_jobserver @job_name = @JobName, @server_name = N'(local)';

    COMMIT TRANSACTION;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
END CATCH;
GO