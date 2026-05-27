-- Run after procedure deployment
EXEC dbo.SP_Sync_ENSEvents
    @FullLoad = 1,
    @SetReadOnly = 0;  -- Keep writable for incremental syncs