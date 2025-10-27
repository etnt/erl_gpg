%%% @doc OTP supervisor for the erl_gpg application.
%%%
%%% This supervisor currently has no permanent children. Worker processes
%%% for GPG operations are spawned dynamically by the API module as short-lived
%%% processes that terminate when the operation completes.
%%%
%%% @end
-module(erl_gpg_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%% @doc Start the supervisor.
%%% @returns `{ok, Pid}' on success, or `{error, Reason}' on failure
%%% @end
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%% @private
%%% @doc Supervisor callback to initialize child specifications.
%%% Currently returns an empty child spec list as workers are spawned dynamically.
%%% @end
init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 10,
        period => 10
    },
    ChildSpecs = [],
    {ok, {SupFlags, ChildSpecs}}.
