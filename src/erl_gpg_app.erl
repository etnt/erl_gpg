%%% @doc OTP application behavior for erl_gpg.
%%%
%%% This module implements the OTP application behavior, starting the
%%% supervisor when the application is started.
%%%
%%% Start the application with:
%%% ```
%%% application:start(erl_gpg).
%%% '''
%%%
%%% @end
-module(erl_gpg_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%%% @private
%%% @doc Application start callback.
%%% Starts the erl_gpg supervisor.
%%% @end
start(_StartType, _StartArgs) ->
    erl_gpg_sup:start_link().

%%% @private
%%% @doc Application stop callback.
%%% @end
stop(_State) ->
    ok.
