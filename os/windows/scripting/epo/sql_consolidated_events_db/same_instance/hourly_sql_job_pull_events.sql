USE msdb;
GO

DECLARE @JobName NVARCHAR(128) = N'Trellix ENS - Incremental Sync (Auto-Adjust Schedule)';

IF EXISTS (SELECT job_id FROM sysjobs WHERE name = @JobName)
    EXEC sp_delete_job @job_name = @JobName;

EXEC sp_add_job
    @job_name = @JobName,
    @enabled = 1,
    @description = N'Incremental sync with pre-test, duration logging, and automatic schedule adjustment if duration approaches/exceeds 1 hour.',
    @owner_login_name = N'sa';

-- Step 1: Run sync (includes pre-test & duration)
EXEC sp_add_jobstep
    @job_name = @JobName,
    @step_name = N'Run Sync',
    @subsystem = N'TSQL',
    @command = N'EXEC ConsolidatedEventsENS.dbo.SP_Sync_ENSEvents;',
    @database_name = N'ConsolidatedEventsENS',
    @on_success_action = 3,  -- Next step
    @on_fail_action = 2;

-- Step 2: Auto-adjust schedule
EXEC sp_add_jobstep
    @job_name = @JobName,
    @step_name = N'Auto-Adjust Schedule',
    @subsystem = N'TSQL',
    @command = N'
    DECLARE @AvgDuration INT, @NewInterval INT = 1, @ScheduleID INT;

    SELECT @AvgDuration = AVG(CAST(REPLACE(REPLACE(Status, ''Success ('', ''''), ''s)'', '''') AS INT))
    FROM (
        SELECT TOP 10 Status
        FROM ConsolidatedEventsENS.dbo.SyncWatermark
        WHERE Status LIKE ''Success (%''
        ORDER BY WatermarkID DESC
    ) T;

    IF @AvgDuration > 3300 SET @NewInterval = 2;   -- >55 min → every 2 hours
    IF @AvgDuration > 6600 SET @NewInterval = 4;   -- >110 min → every 4 hours
    -- Add more tiers as needed

    SELECT @ScheduleID = schedule_id FROM msdb.dbo.sysschedules WHERE name = N''Trellix Dynamic Schedule'';

    IF @NewInterval > 1
    BEGIN
        EXEC msdb.dbo.sp_update_schedule
            @schedule_id = @ScheduleID,
            @freq_subday_interval = @NewInterval;
        PRINT CONCAT(N''Schedule adjusted to every '', @NewInterval, N'' hours (avg: '', @AvgDuration, N''s)'');
    END',
    @database_name = N'master',
    @on_success_action = 1,
    @on_fail_action = 2;

-- Dynamic schedule (starts hourly)
EXEC sp_add_schedule
    @schedule_name = N'Trellix Dynamic Schedule',
    @freq_type = 4,
    @freq_interval = 1,
    @freq_subday_type = 8,
    @freq_subday_interval = 1,
    @active_start_time = 000000;

EXEC sp_attach_schedule
    @job_name = @JobName,
    @schedule_name = N'Trellix Dynamic Schedule';

EXEC sp_add_jobserver @job_name = @JobName;

PRINT N'Job with auto-adjustment deployed. Monitors last 10 runs.';