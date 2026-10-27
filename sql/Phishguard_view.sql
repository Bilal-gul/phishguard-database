use PhishGuardDB;
go

create or alter view dbo.analysis_history
as
select
    u.user_id,
    u.username,
    uu.url_id,
    uu.url,
    d.domain_name,
    d.tranco_rank,
    uu.submitted_at,
    p.prediction_id,
    m.model_name,
    p.predicted_label,
    p.probability,
    p.predicted_at,
    sa.alert_id,
    sa.reason,
    sa.severity,
    sa.is_reviewed
from dbo.user_urls as uu
inner join dbo.users as u
    on u.user_id = uu.user_id
inner join dbo.domains as d
    on d.domain_id = uu.domain_id
left join dbo.predictions as p
    on p.url_id = uu.url_id
left join dbo.models as m
    on m.model_id = p.model_id
left join dbo.suspicious_analyses as sa
    on sa.prediction_id = p.prediction_id;
go

