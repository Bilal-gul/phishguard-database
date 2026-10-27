use PhishGuardDB;
go

create or alter trigger dbo.trg_user_urls_activity_log
on dbo.user_urls
after insert
as
begin
    set nocount on;

    insert into dbo.activity_logs (user_id, action)
    select i.user_id, N'URL_ANALYSIS'
    from inserted as i;
end;
go


create or alter trigger dbo.trg_predictions_suspicious_analysis
on dbo.predictions
after insert
as
begin
    set nocount on;

    insert into dbo.suspicious_analyses        (prediction_id, reason, severity)
    select
        i.prediction_id,
        concat(
            N'URL, model tarafından phishing olarak sınıflandırıldı. ',
            N'Phishing tahmin güveni: ',
            case
                when i.probability >= 0.85 then N'yüksek'
                when i.probability >= 0.60 then N'orta'
                else N'düşük'
            end,
            N' (',
            convert(varchar(20), cast(i.probability * 100.0 as decimal(5,2))),
            N'%).'
        ) as reason,
        case
            when i.probability >= 0.85 then 'high'
            when i.probability >= 0.60 then 'medium'
            else 'low'
        end as severity
    from inserted as i
    where i.predicted_label = 0;
end;
go