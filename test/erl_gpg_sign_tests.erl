%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests for erl_gpg sign and sign_detached functions.
%%%
%%% These tests verify the GPG signing functionality added to erl_gpg.
%%% Note: These tests require a GPG key to be available for testing.
%%% Set the ERL_GPG_TEST_KEY environment variable to a test key ID,
%%% or the tests will be skipped.
%%% @end
%%%-------------------------------------------------------------------
-module(erl_gpg_sign_tests).

-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test Fixtures
%%%===================================================================

%% Check if we have a test GPG key configured
has_test_key() ->
    case os:getenv("ERL_GPG_TEST_KEY") of
        false -> false;
        "" -> false;
        KeyID -> {true, KeyID}
    end.

%% Sample data for testing
test_data() ->
    <<"This is a test message for GPG signing.\n",
      "It contains multiple lines.\n",
      "And some special characters: !@#$%^&*()\n">>.

%%%===================================================================
%%% Test Groups
%%%===================================================================

sign_test_() ->
    {setup,
     fun setup_sign/0,
     fun cleanup_sign/1,
     fun(SetupData) ->
         [
          {"Sign with default options", fun() -> sign_default_test(SetupData) end},
          {"Sign with custom options", fun() -> sign_custom_options_test(SetupData) end},
          {"Sign with invalid key ID", fun() -> sign_invalid_key_test(SetupData) end},
          {"Sign empty data", fun() -> sign_empty_data_test(SetupData) end}
         ]
     end}.

sign_detached_test_() ->
    {setup,
     fun setup_sign_detached/0,
     fun cleanup_sign_detached/1,
     fun(SetupData) ->
         [
          {"Sign detached with default options", fun() -> sign_detached_default_test(SetupData) end},
          {"Sign detached with custom options", fun() -> sign_detached_custom_options_test(SetupData) end},
          {"Sign detached with invalid key ID", fun() -> sign_detached_invalid_key_test(SetupData) end},
          {"Verify detached signature format", fun() -> sign_detached_format_test(SetupData) end}
         ]
     end}.

%%%===================================================================
%%% Setup and Cleanup
%%%===================================================================

setup_sign() ->
    case has_test_key() of
        false ->
            {skip, "No test GPG key configured (set ERL_GPG_TEST_KEY)"};
        {true, KeyID} ->
            #{key_id => KeyID, data => test_data()}
    end.

cleanup_sign(_SetupData) ->
    ok.

setup_sign_detached() ->
    case has_test_key() of
        false ->
            {skip, "No test GPG key configured (set ERL_GPG_TEST_KEY)"};
        {true, KeyID} ->
            #{key_id => KeyID, data => test_data()}
    end.

cleanup_sign_detached(_SetupData) ->
    ok.

%%%===================================================================
%%% Sign Tests
%%%===================================================================

sign_default_test({skip, Reason}) ->
    {skip, Reason};
sign_default_test(#{key_id := KeyID, data := Data}) ->
    %% Test basic sign operation
    Result = erl_gpg_api:sign(Data, KeyID),
    
    ?assertMatch({ok, _}, Result),
    {ok, SignResult} = Result,
    
    %% Verify the result is a map with expected fields
    ?assert(is_map(SignResult)),
    ?assert(maps:is_key(stdout, SignResult)),
    ?assert(maps:is_key(exit, SignResult)),
    
    %% Verify exit is ok (success)
    ?assertEqual(ok, maps:get(exit, SignResult)),
    
    %% Verify stdout contains signature
    Stdout = maps:get(stdout, SignResult),
    ?assert(is_binary(Stdout)),
    ?assert(byte_size(Stdout) > 0),
    
    %% Clearsign should contain the original message and signature
    ?assert(binary:match(Stdout, <<"BEGIN PGP SIGNED MESSAGE">>) =/= nomatch),
    ?assert(binary:match(Stdout, <<"BEGIN PGP SIGNATURE">>) =/= nomatch),
    ?assert(binary:match(Stdout, <<"END PGP SIGNATURE">>) =/= nomatch).

sign_custom_options_test({skip, Reason}) ->
    {skip, Reason};
sign_custom_options_test(#{key_id := KeyID, data := Data}) ->
    %% Test sign with custom options
    Options = [{armor, true}],
    Result = erl_gpg_api:sign(Data, KeyID, Options),
    
    ?assertMatch({ok, _}, Result),
    {ok, SignResult} = Result,
    
    %% Verify basic structure
    ?assertEqual(ok, maps:get(exit, SignResult)),
    
    %% Verify signature format
    Stdout = maps:get(stdout, SignResult),
    ?assert(binary:match(Stdout, <<"BEGIN PGP SIGNED MESSAGE">>) =/= nomatch).

sign_invalid_key_test({skip, Reason}) ->
    {skip, Reason};
sign_invalid_key_test(#{data := Data}) ->
    %% Test with an invalid key ID
    InvalidKeyID = "INVALID_KEY_ID_12345678",
    Result = erl_gpg_api:sign(Data, InvalidKeyID),
    
    %% Should return error or non-ok exit status
    case Result of
        {ok, SignResult} ->
            %% If it returns ok, exit should be error
            Exit = maps:get(exit, SignResult),
            ?assertMatch({error, _}, Exit);
        {error, _Reason} ->
            %% Error is also acceptable
            ok
    end.

sign_empty_data_test({skip, Reason}) ->
    {skip, Reason};
sign_empty_data_test(#{key_id := KeyID}) ->
    %% Test signing empty data
    EmptyData = <<>>,
    Result = erl_gpg_api:sign(EmptyData, KeyID),
    
    %% Should still succeed (GPG can sign empty data)
    ?assertMatch({ok, _}, Result),
    {ok, SignResult} = Result,
    ?assertEqual(ok, maps:get(exit, SignResult)).

%%%===================================================================
%%% Sign Detached Tests
%%%===================================================================

sign_detached_default_test({skip, Reason}) ->
    {skip, Reason};
sign_detached_default_test(#{key_id := KeyID, data := Data}) ->
    %% Test basic sign_detached operation
    Result = erl_gpg_api:sign_detached(Data, KeyID, ""),
    
    ?assertMatch({ok, _}, Result),
    {ok, SignResult} = Result,
    
    %% Verify the result structure
    ?assert(is_map(SignResult)),
    ?assert(maps:is_key(stdout, SignResult)),
    ?assert(maps:is_key(exit, SignResult)),
    
    %% Verify exit is ok (success)
    ?assertEqual(ok, maps:get(exit, SignResult)),
    
    %% Verify stdout contains detached signature
    Stdout = maps:get(stdout, SignResult),
    ?assert(is_binary(Stdout)),
    ?assert(byte_size(Stdout) > 0),
    
    %% Detached signature should NOT contain original message
    %% but should contain signature blocks
    ?assert(binary:match(Stdout, <<"BEGIN PGP SIGNATURE">>) =/= nomatch),
    ?assert(binary:match(Stdout, <<"END PGP SIGNATURE">>) =/= nomatch),
    
    %% Should NOT contain "SIGNED MESSAGE" (that's clearsign)
    ?assertEqual(nomatch, binary:match(Stdout, <<"BEGIN PGP SIGNED MESSAGE">>)).

sign_detached_custom_options_test({skip, Reason}) ->
    {skip, Reason};
sign_detached_custom_options_test(#{key_id := KeyID, data := Data}) ->
    %% Test sign_detached with custom options
    Options = [{armor, true}],
    Result = erl_gpg_api:sign_detached(Data, KeyID, "", Options),
    
    ?assertMatch({ok, _}, Result),
    {ok, SignResult} = Result,
    
    %% Verify basic structure
    ?assertEqual(ok, maps:get(exit, SignResult)),
    
    %% Verify signature format
    Stdout = maps:get(stdout, SignResult),
    ?assert(binary:match(Stdout, <<"BEGIN PGP SIGNATURE">>) =/= nomatch).

sign_detached_invalid_key_test({skip, Reason}) ->
    {skip, Reason};
sign_detached_invalid_key_test(#{data := Data}) ->
    %% Test with an invalid key ID
    InvalidKeyID = "INVALID_KEY_ID_12345678",
    Result = erl_gpg_api:sign_detached(Data, InvalidKeyID, ""),
    
    %% Should return error or non-ok exit status
    case Result of
        {ok, SignResult} ->
            Exit = maps:get(exit, SignResult),
            ?assertMatch({error, _}, Exit);
        {error, _Reason} ->
            ok
    end.

sign_detached_format_test({skip, Reason}) ->
    {skip, Reason};
sign_detached_format_test(#{key_id := KeyID, data := Data}) ->
    %% Test that detached signature has correct PEM format
    Result = erl_gpg_api:sign_detached(Data, KeyID, ""),
    
    ?assertMatch({ok, _}, Result),
    {ok, SignResult} = Result,
    
    Stdout = maps:get(stdout, SignResult),
    
    %% Verify PEM format structure
    ?assert(binary:match(Stdout, <<"-----BEGIN PGP SIGNATURE-----">>) =/= nomatch),
    ?assert(binary:match(Stdout, <<"-----END PGP SIGNATURE-----">>) =/= nomatch),
    
    %% Verify it's base64-encoded (contains valid base64 chars)
    Lines = binary:split(Stdout, <<"\n">>, [global]),
    
    %% Find signature lines (between BEGIN and END, excluding headers)
    SignatureLines = lists:filter(
        fun(Line) ->
            case binary:match(Line, <<"-----">>) of
                nomatch ->
                    case binary:match(Line, <<"Version:">>) of
                        nomatch -> byte_size(Line) > 0;
                        _ -> false
                    end;
                _ -> false
            end
        end,
        Lines
    ),
    
    %% At least one line should contain base64 data
    ?assert(length(SignatureLines) > 0),
    
    %% Check that signature lines contain valid base64 characters
    lists:foreach(
        fun(Line) ->
            %% Base64 uses A-Z, a-z, 0-9, +, /, =
            ?assert(
                lists:all(
                    fun(C) ->
                        (C >= $A andalso C =< $Z) orelse
                        (C >= $a andalso C =< $z) orelse
                        (C >= $0 andalso C =< $9) orelse
                        C =:= $+ orelse C =:= $/ orelse C =:= $=
                    end,
                    binary_to_list(Line)
                )
            )
        end,
        SignatureLines
    ).

%%%===================================================================
%%% Integration Tests
%%%===================================================================

%% Test that sign and sign_detached produce different outputs
sign_vs_sign_detached_test_() ->
    case has_test_key() of
        false ->
            {skip, "No test GPG key configured (set ERL_GPG_TEST_KEY)"};
        {true, KeyID} ->
            Data = test_data(),
            
            %% Get both types of signatures
            {ok, ClearSign} = erl_gpg_api:sign(Data, KeyID),
            {ok, DetachedSign} = erl_gpg_api:sign_detached(Data, KeyID, ""),
            
            ClearStdout = maps:get(stdout, ClearSign),
            DetachedStdout = maps:get(stdout, DetachedSign),
            
            [
             ?_assertNotEqual(ClearStdout, DetachedStdout),
             ?_assert(binary:match(ClearStdout, <<"BEGIN PGP SIGNED MESSAGE">>) =/= nomatch),
             ?_assertEqual(nomatch, binary:match(DetachedStdout, <<"BEGIN PGP SIGNED MESSAGE">>)),
             ?_assert(binary:match(ClearStdout, Data) =/= nomatch),
             ?_assertEqual(nomatch, binary:match(DetachedStdout, Data))
            ]
    end.
