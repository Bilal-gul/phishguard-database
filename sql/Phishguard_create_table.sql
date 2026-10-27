use PhishGuardDB;
go

create table dbo.users(
	user_id int primary key identity(1,1),
	username nvarchar(75) not null unique,
	email nvarchar(255) not null unique,
	password_hash nvarchar(255) not null,
	created_at datetime2 not null default sysdatetime(),
	is_active bit not null default 1
)
go

create table dbo.domains(
	domain_id int primary key identity(1,1),
	domain_name nvarchar(255) not null unique,
	tranco_rank int null,
	created_at datetime2 not null default sysdatetime(),

	constraint CK_domains_tranco_rank
		check (tranco_rank is null or tranco_rank >= 1)
)
go

create table dbo.models(
	model_id int primary key identity(1,1),
	model_name nvarchar(100) not null,
	algorithm nvarchar(100) not null,
	version nvarchar(50) not null,
	file_path nvarchar(500) not null,
	created_at datetime2 not null default sysdatetime(),
	is_active bit not null default 1
)
go 

create table dbo.features_dictionary(
	feature_id int primary key identity(1,1),
	feature_name nvarchar(100) not null unique,
	description nvarchar(max) null,
	data_type nvarchar(50) not null,
	created_at datetime2 not null default sysdatetime(),
	is_active bit not null default 1
)
go

create table dbo.sessions(
	session_id int primary key identity(1,1),
	user_id int not null,
	login_at datetime2 not null default sysdatetime(),
	logout_at datetime2 null,

	constraint FK_sessions_users
		foreign key (user_id)
		references dbo.users(user_id),

	constraint CK_sessions_logout
		check (logout_at is null or logout_at >= login_at)
)
go

create table dbo.user_urls(
	url_id int primary key identity(1,1),
	user_id int not null,
	domain_id int not null,
	url nvarchar(2048) not null,
	submitted_at datetime2 not null default sysdatetime(),

	constraint FK_user_urls_users
		foreign key (user_id)
		references dbo.users(user_id),

	constraint FK_user_urls_domains
		foreign key (domain_id)
		references dbo.domains(domain_id)
)
go

create table dbo.model_features(
	model_id int not null,
	feature_id int not null,

	constraint PK_model_features
		primary key (model_id, feature_id),

	constraint FK_model_features_models
		foreign key (model_id)
		references dbo.models(model_id),

	constraint FK_model_features_features
		foreign key (feature_id)
		references dbo.features_dictionary(feature_id)
)
go


create table dbo.activity_logs(
	log_id int primary key identity(1,1),
	user_id int not null,
	action nvarchar(30) not null,
	created_at datetime2 not null default sysdatetime(),

	constraint FK_activity_logs_users
		foreign key (user_id)
		references dbo.users(user_id),

	constraint CK_activity_logs_action
		check (action in (
			'REGISTER',
            'LOGIN',
            'URL_ANALYSIS',
            'LOGOUT'
		))

)
go 

create table dbo.predictions (
    prediction_id int primary key identity(1,1),
    url_id int not null,
    model_id int not null,
    predicted_label tinyint not null,
    probability decimal(9,8) not null,
    predicted_at datetime2 not null default sysdatetime(),

    constraint FK_predictions_user_urls
        foreign key (url_id)
        references dbo.user_urls(url_id),

    constraint FK_predictions_models
        foreign key (model_id)
        references dbo.models(model_id),

    constraint CK_predictions_label
        check (predicted_label in (0, 1)),

    constraint CK_predictions_probability
        check (probability >= 0 and probability <= 1)
)
go

create table dbo.suspicious_analyses (
    alert_id int primary key identity(1,1),
    prediction_id int not null,
    reason nvarchar(500) not null,
    severity nvarchar(50) not null,
    created_at datetime2 not null default sysdatetime(),
    is_reviewed bit not null default 0,

	constraint FK_suspicious_analyses_predictions
        foreign key (prediction_id)
        references dbo.predictions(prediction_id)
)
go
