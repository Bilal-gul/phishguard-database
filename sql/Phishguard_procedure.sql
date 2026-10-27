use PhishGuardDB;
go

create or alter procedure dbo.record_url_analysis
    @user_id int,
    @url nvarchar(2048),
    @domain_name nvarchar(255),
    @tranco_rank int = null
as
begin
    set nocount on;
    set xact_abort on;

    declare @domain_id int;
    declare @url_id int;

    begin try
        begin transaction;

        select @domain_id = domain_id
        from dbo.domains with (updlock, holdlock)
        where domain_name = @domain_name;

        if @domain_id is null
        begin
            insert into dbo.domains (domain_name, tranco_rank)
            values (@domain_name, @tranco_rank);

            set @domain_id = convert(int, scope_identity());
        end;

        insert into dbo.user_urls (user_id, domain_id, url)
        values (@user_id, @domain_id, @url);

        set @url_id = convert(int, scope_identity());

        commit transaction;

        select @url_id as url_id;
    end try
    begin catch
        if @@trancount > 0
            rollback transaction;

        throw;
    end catch;
end;
go
