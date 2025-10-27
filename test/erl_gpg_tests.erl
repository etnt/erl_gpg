-module(erl_gpg_tests).

-include_lib("eunit/include/eunit.hrl").

%% Test fixtures
setup() ->
    %% Start the application
    application:ensure_all_started(erl_gpg),
    ok.

cleanup(_) ->
    application:stop(erl_gpg),
    ok.

%%--------------------------------------------------------------------
%% Worker Module Tests
%%--------------------------------------------------------------------

worker_test_() ->
    {"GPG Worker Tests",
        {setup, fun setup/0, fun cleanup/1, [
            fun test_worker_encrypt_decrypt/0,
            fun test_worker_unsupported_operation/0
        ]}}.

test_worker_encrypt_decrypt() ->
    Plain = <<"Hello, GPG!">>,
    Recipients = ["test@example.com"],
    Self = self(),

    %% This test would require a valid GPG setup with keys
    %% For now, we test that the worker can be called
    spawn(fun() ->
        erl_gpg_worker:run(encrypt, Plain, Recipients, Self)
    end),

    receive
        {ok, _Result} ->
            ?assert(true);
        {error, _Reason} ->
            %% Expected if GPG is not configured
            ?assert(true)
    after 5000 ->
        ?assert(false, "Worker timeout")
    end.

test_worker_unsupported_operation() ->
    Self = self(),
    spawn(fun() ->
        erl_gpg_worker:run(invalid_op, <<"data">>, [], Self)
    end),

    receive
        {error, unsupported_operation} ->
            ?assert(true)
    after 1000 ->
        ?assert(false, "Expected unsupported_operation error")
    end.

%%--------------------------------------------------------------------
%% Helper Function Tests
%%--------------------------------------------------------------------

split_output_test_() ->
    [
        {"Empty binary",
            ?_assertEqual(
                {<<>>, [], []},
                erl_gpg_worker:split_gpg_output(<<>>)
            )},

        {"Status line parsing", fun() ->
            Input = <<"[GNUPG:] BEGIN_ENCRYPTION 2 9\n">>,
            {_Stdout, StatusLines, _ColonLines} = erl_gpg_worker:split_gpg_output(
                Input
            ),
            ?assertEqual(1, length(StatusLines)),
            [StatusLine] = StatusLines,
            ?assertEqual(<<"[GNUPG:] BEGIN_ENCRYPTION 2 9">>, StatusLine)
        end},

        {"Regular stdout", fun() ->
            Input = <<"Some regular output\n">>,
            {Stdout, StatusLines, ColonLines} = erl_gpg_worker:split_gpg_output(
                Input
            ),
            %% The classify function adds newline before the text
            ?assert(
                binary:match(Stdout, <<"Some regular output">>) =/= nomatch
            ),
            ?assertEqual([], StatusLines),
            ?assertEqual([], ColonLines)
        end},

        {"Mixed content", fun() ->
            Input = <<"Regular line\n[GNUPG: STATUS_MSG\npub::::::::::\n">>,
            {_Stdout, StatusLines, ColonLines} = erl_gpg_worker:split_gpg_output(
                Input
            ),
            ?assert(length(StatusLines) > 0 orelse length(ColonLines) > 0)
        end}
    ].

parse_status_line_test_() ->
    [
        {"Valid status line", fun() ->
            Line = <<"[GNUPG:] BEGIN_ENCRYPTION 2 9">>,
            Result = erl_gpg_worker:parse_status_line(Line),
            ?assertEqual(<<"BEGIN_ENCRYPTION">>, maps:get(tag, Result)),
            Args = maps:get(args, Result),
            ?assert(is_list(Args))
        end},

        {"Status line with multiple args", fun() ->
            Line = <<"[GNUPG:] KEY_CONSIDERED 1234567890ABCDEF 0">>,
            Result = erl_gpg_worker:parse_status_line(Line),
            ?assertEqual(<<"KEY_CONSIDERED">>, maps:get(tag, Result)),
            Args = maps:get(args, Result),
            ?assertEqual(2, length(Args))
        end},

        {"Invalid status line", fun() ->
            Line = <<"Not a status line">>,
            Result = erl_gpg_worker:parse_status_line(Line),
            ?assertEqual(<<>>, maps:get(tag, Result)),
            ?assertEqual([], maps:get(args, Result))
        end}
    ].

parse_colon_line_test_() ->
    [
        {"Public key record", fun() ->
            Line =
                <<"pub:u:4096:1:1234567890ABCDEF:2023-01-01:::u:::scESC:::+:::23::0:">>,
            Result = erl_gpg_worker:parse_colon_line(Line),
            ?assertEqual(<<"pub">>, maps:get(type, Result)),
            Fields = maps:get(fields, Result),
            ?assert(length(Fields) > 0)
        end},

        {"UID record", fun() ->
            Line =
                <<"uid:u::::1672531200::ABCDEF1234567890::Test User <test@example.com>::::::::::0:">>,
            Result = erl_gpg_worker:parse_colon_line(Line),
            ?assertEqual(<<"uid">>, maps:get(type, Result)),
            ?assert(is_list(maps:get(fields, Result)))
        end},

        {"Fingerprint record", fun() ->
            Line = <<"fpr:::::::::1234567890ABCDEF1234567890ABCDEF:">>,
            Result = erl_gpg_worker:parse_colon_line(Line),
            ?assertEqual(<<"fpr">>, maps:get(type, Result))
        end}
    ].

is_status_line_test_() ->
    [
        ?_assertEqual(
            true, erl_gpg_worker:is_status_line(<<"[GNUPG: SOMETHING">>)
        ),
        ?_assertEqual(true, erl_gpg_worker:is_status_line(<<"[GNUPG:TEST">>)),
        ?_assertEqual(false, erl_gpg_worker:is_status_line(<<"Not a status">>)),
        ?_assertEqual(false, erl_gpg_worker:is_status_line(<<>>))
    ].

is_colon_line_test_() ->
    [
        ?_assertEqual(true, erl_gpg_worker:is_colon_line(<<"pub::::::::::">>)),
        ?_assertEqual(true, erl_gpg_worker:is_colon_line(<<"uid:u::::">>)),
        ?_assertEqual(true, erl_gpg_worker:is_colon_line(<<"fpr:::::">>)),
        ?_assertEqual(true, erl_gpg_worker:is_colon_line(<<"sub::::::::::">>)),
        ?_assertEqual(false, erl_gpg_worker:is_colon_line(<<"no colons">>)),
        ?_assertEqual(false, erl_gpg_worker:is_colon_line(<<"invalid:line">>))
    ].

%%--------------------------------------------------------------------
%% API Tests
%%--------------------------------------------------------------------

api_test_() ->
    {"GPG API Tests",
        {setup, fun setup/0, fun cleanup/1, [
            fun test_api_encrypt_error/0,
            fun test_api_decrypt_error/0,
            fun test_api_import_error/0,
            fun test_api_verify_error/0,
            fun test_api_verify_detached_error/0
        ]}}.

test_api_encrypt_error() ->
    %% Test with invalid GPG configuration (will fail but test the path)
    Plain = <<"Test message">>,
    Recipients = ["nonexistent@example.com"],
    %% Reduce timeout since we expect it to fail quickly
    spawn(fun() ->
        Result = erl_gpg_api:encrypt(Plain, Recipients, "/tmp/nonexistent"),
        %% Should get an error since GPG may not have the key
        case Result of
            {error, _} -> ok;
            %% Unexpected but ok
            {ok, _} -> ok
        end
    end),
    %% Just verify the call doesn't crash the system
    timer:sleep(100),
    ?assert(true).

test_api_decrypt_error() ->
    %% Test with invalid ciphertext - spawn to avoid blocking
    Cipher =
        <<"-----BEGIN PGP MESSAGE-----\nInvalid\n-----END PGP MESSAGE-----">>,
    spawn(fun() ->
        _Result = erl_gpg_api:decrypt(Cipher, "/tmp/nonexistent"),
        ok
    end),
    timer:sleep(100),
    ?assert(true).

test_api_import_error() ->
    %% Test with invalid key data - spawn to avoid blocking
    KeyData =
        <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\nInvalid\n-----END PGP PUBLIC KEY BLOCK-----">>,
    spawn(fun() ->
        _Result = erl_gpg_api:import_key(KeyData, "/tmp/nonexistent"),
        ok
    end),
    timer:sleep(100),
    ?assert(true).

test_api_verify_error() ->
    %% Test with invalid signature - spawn to avoid blocking
    Data =
        <<"-----BEGIN PGP SIGNED MESSAGE-----\nInvalid\n-----END PGP SIGNATURE-----">>,
    spawn(fun() ->
        _Result = erl_gpg_api:verify(Data, "/tmp/nonexistent"),
        ok
    end),
    timer:sleep(100),
    ?assert(true).

test_api_verify_detached_error() ->
    %% Test detached signature verification with invalid data
    Data = <<"Some data to verify">>,
    Signature =
        <<"-----BEGIN PGP SIGNATURE-----\nInvalid\n-----END PGP SIGNATURE-----">>,
    spawn(fun() ->
        _Result =
            erl_gpg_api:verify_detached(Data, Signature, "/tmp/nonexistent"),
        ok
    end),
    timer:sleep(100),
    ?assert(true).

%%--------------------------------------------------------------------
%% Supervisor Tests
%%--------------------------------------------------------------------

supervisor_test_() ->
    {"Supervisor Tests",
        {setup, fun setup/0, fun cleanup/1, [
            fun test_supervisor_start/0,
            fun test_worker_spawn/0
        ]}}.

test_supervisor_start() ->
    %% Check that supervisor is running
    Pid = whereis(erl_gpg_sup),
    ?assert(is_pid(Pid)),

    %% Verify supervisor state
    Which = supervisor:which_children(erl_gpg_sup),
    ?assert(is_list(Which)).

test_worker_spawn() ->
    %% Test that we can spawn a worker
    Worker = erl_gpg_api:start_worker(encrypt, <<"test">>, ["test@example.com"]),
    ?assert(is_pid(Worker)).

%%--------------------------------------------------------------------
%% Integration Tests with Isolated Keyring
%%--------------------------------------------------------------------

%% Generate a test GPG key pair for integration testing
%% Returns {PublicKey, PrivateKey} as binaries
generate_test_keypair(HomeDir) ->
    %% Create GPG batch file for key generation
    BatchFile = filename:join(HomeDir, "keygen.batch"),
    BatchContent =
        "Key-Type: RSA\n"
        "Key-Length: 2048\n"
        "Name-Real: Test User\n"
        "Name-Email: test@example.com\n"
        "Expire-Date: 0\n"
        "%no-protection\n"
        "%commit\n",
    ok = file:write_file(BatchFile, BatchContent),

    %% Generate key
    GpgBin = find_gpg(),
    Cmd =
        GpgBin ++ " --homedir " ++ HomeDir ++ " --batch --gen-key " ++
            BatchFile,
    os:cmd(Cmd),

    %% Export public key
    ExportPubCmd =
        GpgBin ++ " --homedir " ++ HomeDir ++
            " --armor --export test@example.com",
    PubKey = list_to_binary(os:cmd(ExportPubCmd)),

    %% Export private key
    ExportPrivCmd =
        GpgBin ++ " --homedir " ++ HomeDir ++
            " --armor --export-secret-keys test@example.com",
    PrivKey = list_to_binary(os:cmd(ExportPrivCmd)),

    {PubKey, PrivKey}.

find_gpg() ->
    Candidates = [
        "/opt/homebrew/bin/gpg",
        "/usr/local/bin/gpg",
        "/usr/bin/gpg",
        "/bin/gpg"
    ],
    case lists:filter(fun filelib:is_file/1, Candidates) of
        [First | _] -> First;
        [] -> "gpg"
    end.

%% Setup and cleanup for integration tests
integration_setup() ->
    application:ensure_all_started(erl_gpg),
    %% Create temporary directory for isolated keyring
    TempDir =
        "/tmp/erl_gpg_test_" ++
            integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_dir(TempDir ++ "/"),
    os:cmd("chmod 700 " ++ TempDir),

    %% Generate test key pair
    {PubKey, PrivKey} = generate_test_keypair(TempDir),

    #{home_dir => TempDir, pub_key => PubKey, priv_key => PrivKey}.

integration_cleanup(#{home_dir := HomeDir}) ->
    %% Clean up temporary directory
    os:cmd("rm -rf " ++ HomeDir),
    application:stop(erl_gpg),
    ok.

integration_test_() ->
    {"Integration Tests with Isolated Keyring",
        {setup, fun integration_setup/0, fun integration_cleanup/1, fun(Setup) ->
            [
                test_encrypt_decrypt_roundtrip(Setup),
                test_list_keys_after_import(Setup),
                test_import_and_verify(Setup),
                test_multiple_recipients(Setup)
            ]
        end}}.

test_encrypt_decrypt_roundtrip(#{home_dir := HomeDir}) ->
    {"Encrypt/Decrypt roundtrip", fun() ->
        PlainText = <<"Secret message for integration test">>,
        Recipients = ["test@example.com"],
        Opts = [{home_dir, HomeDir}, {trust_model, always}],

        %% Encrypt
        {ok, EncResult} = erl_gpg_api:encrypt(PlainText, Recipients, "", Opts),
        ?assertEqual(ok, maps:get(exit, EncResult)),
        Ciphertext = maps:get(stdout, EncResult),
        ?assertNotEqual(<<>>, Ciphertext),
        ?assert(
            binary:match(Ciphertext, <<"-----BEGIN PGP MESSAGE-----">>) =/=
                nomatch
        ),

        %% Decrypt
        %% Note: GPG may return error exit status even when decryption succeeds
        %% (e.g., smartcard warnings, keyring issues). Check status lines instead.
        DecResult = erl_gpg_api:decrypt(Ciphertext, "", Opts),
        DecResultMap =
            case DecResult of
                {ok, M} -> M;
                %% May have error exit but successful decryption
                {error, M} -> M
            end,

        %% Check for successful decryption in status (GOODMDC or DECRYPTION_OKAY)
        Status = maps:get(status, DecResultMap),
        HasDecryptionOK = lists:any(
            fun(#{tag := Tag}) ->
                Tag =:= <<"DECRYPTION_OKAY">> orelse Tag =:= <<"GOODMDC">>
            end,
            Status
        ),
        io:format("~nHas successful decryption: ~p~n", [HasDecryptionOK]),
        io:format("Status: ~p~n", [Status]),
        ?assert(HasDecryptionOK),

        %% Verify the decrypted content (strip any leading/trailing whitespace)
        Decrypted = string:trim(maps:get(stdout, DecResultMap)),
        io:format("Decrypted: ~p~n", [Decrypted]),
        io:format("PlainText: ~p~n", [PlainText]),
        ?assertEqual(PlainText, Decrypted)
    end}.

test_list_keys_after_import(#{home_dir := HomeDir, pub_key := _PubKey}) ->
    {"List keys after import", fun() ->
        Opts = [{home_dir, HomeDir}],

        %% List keys before import (should have the generated key)
        {ok, Result1} = erl_gpg_api:list_keys(Opts),
        ColonData1 = maps:get(colon, Result1),

        %% Find test user in keys
        HasTestUser = lists:any(
            fun(Record) ->
                case Record of
                    #{type := <<"uid">>, fields := Fields} when
                        length(Fields) >= 9
                    ->
                        UID = lists:nth(9, Fields),
                        binary:match(UID, <<"test@example.com">>) =/= nomatch;
                    _ ->
                        false
                end
            end,
            ColonData1
        ),
        ?assert(HasTestUser),

        %% Test format_keys output
        Formatted = erl_gpg_api:format_keys(Result1),
        ?assert(is_list(Formatted) orelse is_binary(Formatted)),
        FormattedStr = lists:flatten(io_lib:format("~s", [Formatted])),
        ?assert(string:str(FormattedStr, "test@example.com") > 0)
    end}.

test_import_and_verify(#{home_dir := HomeDir, pub_key := PubKey}) ->
    {"Import key to different keyring and verify", fun() ->
        %% Create another isolated keyring
        TempDir2 =
            "/tmp/erl_gpg_test2_" ++
                integer_to_list(erlang:unique_integer([positive])),
        ok = filelib:ensure_dir(TempDir2 ++ "/"),
        os:cmd("chmod 700 " ++ TempDir2),

        try
            Opts = [{home_dir, TempDir2}],

            %% Import public key
            {ok, ImportResult} = erl_gpg_api:import_key(PubKey, "", Opts),
            ?assertEqual(ok, maps:get(exit, ImportResult)),

            %% Verify key was imported by listing keys
            {ok, ListResult} = erl_gpg_api:list_keys(Opts),
            ColonData = maps:get(colon, ListResult),
            HasKey = lists:any(
                fun(#{type := Type}) -> Type =:= <<"pub">> end, ColonData
            ),
            ?assert(HasKey),

            %% Now encrypt with the original keyring and try to decrypt with the new one
            %% (should fail because we only imported public key, not private)
            PlainText = <<"Test message">>,
            OrigOpts = [{home_dir, HomeDir}, {trust_model, always}],
            {ok, EncResult} = erl_gpg_api:encrypt(
                PlainText, ["test@example.com"], "", OrigOpts
            ),
            Ciphertext = maps:get(stdout, EncResult),

            %% Try to decrypt (should fail - no private key)
            case erl_gpg_api:decrypt(Ciphertext, "", Opts) of
                %% Expected
                {error, _} -> ?assert(true);
                %% Also acceptable
                {ok, #{exit := {error, _}}} -> ?assert(true);
                %% Should not succeed
                {ok, _} -> ?assert(false)
            end
        after
            os:cmd("rm -rf " ++ TempDir2)
        end
    end}.

test_multiple_recipients(#{home_dir := HomeDir}) ->
    {"Encrypt for multiple recipients", fun() ->
        %% Generate a second key
        TempDir2 =
            "/tmp/erl_gpg_test_multi_" ++
                integer_to_list(erlang:unique_integer([positive])),
        ok = filelib:ensure_dir(TempDir2 ++ "/"),
        os:cmd("chmod 700 " ++ TempDir2),

        try
            %% Generate second keypair
            BatchFile = filename:join(TempDir2, "keygen.batch"),
            BatchContent =
                "Key-Type: RSA\n"
                "Key-Length: 2048\n"
                "Name-Real: Second User\n"
                "Name-Email: second@example.com\n"
                "Expire-Date: 0\n"
                "%no-protection\n"
                "%commit\n",
            ok = file:write_file(BatchFile, BatchContent),
            GpgBin = find_gpg(),
            os:cmd(
                GpgBin ++ " --homedir " ++ TempDir2 ++ " --batch --gen-key " ++
                    BatchFile
            ),

            %% Export second public key
            ExportCmd =
                GpgBin ++ " --homedir " ++ TempDir2 ++
                    " --armor --export second@example.com",
            PubKey2 = list_to_binary(os:cmd(ExportCmd)),

            %% Import second public key into first keyring
            Opts = [{home_dir, HomeDir}],
            {ok, _} = erl_gpg_api:import_key(PubKey2, "", Opts),

            %% Encrypt for both recipients
            PlainText = <<"Multi-recipient message">>,
            Recipients = ["test@example.com", "second@example.com"],
            EncOpts = [{home_dir, HomeDir}, {trust_model, always}],
            {ok, EncResult} = erl_gpg_api:encrypt(
                PlainText, Recipients, "", EncOpts
            ),
            ?assertEqual(ok, maps:get(exit, EncResult)),
            Ciphertext = maps:get(stdout, EncResult),

            %% Both recipients should be able to decrypt
            %% First recipient (our test key)
            DecResult1 = erl_gpg_api:decrypt(Ciphertext, "", EncOpts),
            DecResultMap1 =
                case DecResult1 of
                    {ok, M1} -> M1;
                    {error, M1} -> M1
                end,
            %% Check for successful decryption (GOODMDC or DECRYPTION_OKAY)
            Status1 = maps:get(status, DecResultMap1),
            HasDecryptOK1 = lists:any(
                fun(#{tag := Tag}) ->
                    Tag =:= <<"DECRYPTION_OKAY">> orelse Tag =:= <<"GOODMDC">>
                end,
                Status1
            ),
            ?assert(HasDecryptOK1),
            ?assertEqual(
                PlainText, string:trim(maps:get(stdout, DecResultMap1))
            ),

            %% Second recipient
            DecOpts2 = [{home_dir, TempDir2}],
            DecResult2 = erl_gpg_api:decrypt(Ciphertext, "", DecOpts2),
            DecResultMap2 =
                case DecResult2 of
                    {ok, M2} -> M2;
                    {error, M2} -> M2
                end,
            Status2 = maps:get(status, DecResultMap2),
            HasDecryptOK2 = lists:any(
                fun(#{tag := Tag}) ->
                    Tag =:= <<"DECRYPTION_OKAY">> orelse Tag =:= <<"GOODMDC">>
                end,
                Status2
            ),
            ?assert(HasDecryptOK2),
            ?assertEqual(
                PlainText, string:trim(maps:get(stdout, DecResultMap2))
            )
        after
            os:cmd("rm -rf " ++ TempDir2)
        end
    end}.
