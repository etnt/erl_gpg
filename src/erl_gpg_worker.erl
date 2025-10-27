%%% @doc GPG worker process for port communication and output parsing.
%%%
%%% This module handles low-level GPG process management, including spawning
%%% the GPG binary via ports, sending input data, and parsing machine-readable
%%% output from GPG's status-fd and with-colons formats.
%%%
%%% == Output Parsing ==
%%%
%%% GPG output is parsed using heuristics:
%%% <ul>
%%%   <li>Status lines begin with "[GNUPG:" from status-fd=2</li>
%%%   <li>Colon lines use colon-separated format from --with-colons</li>
%%% </ul>
%%%
%%% Status lines are parsed into maps: `#{tag => Binary, args => [Binary]}'
%%%
%%% Colon lines are parsed into maps: `#{type => Binary, fields => [Binary]}'
%%%
%%% == Production Considerations ==
%%%
%%% For production use, consider enhancing parsing to:
%%% <ul>
%%%   <li>Trim whitespace and handle text encodings</li>
%%%   <li>Handle multi-line fields properly</li>
%%%   <li>Detect and handle interleaving edge cases</li>
%%%   <li>Adjust heuristics for different GPG versions or locales</li>
%%% </ul>
%%%
%%% @end
-module(erl_gpg_worker).

-export([run/4]).
%% Exported for testing
-export([
    split_gpg_output/1,
    parse_status_line/1,
    parse_status_lines/1,
    parse_colon_line/1,
    parse_colon_lines/1,
    is_status_line/1,
    is_colon_line/1,
    base_args/1,
    base_args/2
]).

-define(TIMEOUT, 15000).

%%% @doc Get the GPG binary path.
%%%
%%% Returns the GPG binary path from application configuration, or automatically
%%% detects it by searching common installation locations.
%%%
%%% The search order is:
%%% <ol>
%%%   <li>Application env variable `gpg_binary' (if set)</li>
%%%   <li>`/opt/homebrew/bin/gpg' (Homebrew on Apple Silicon)</li>
%%%   <li>`/usr/local/bin/gpg' (Homebrew on Intel Mac / Linux)</li>
%%%   <li>`/usr/bin/gpg' (Standard Linux)</li>
%%%   <li>`/bin/gpg' (Alternative)</li>
%%%   <li>System PATH via `os:find_executable/1'</li>
%%% </ol>
%%%
%%% Configure a custom path with:
%%% ```
%%% application:set_env(erl_gpg, gpg_binary, "/custom/path/to/gpg").
%%% '''
%%%
%%% @returns Path to GPG binary as a string
%%% @end
-spec gpg_bin() -> string().
gpg_bin() ->
    case application:get_env(erl_gpg, gpg_binary) of
        {ok, Path} -> Path;
        undefined -> find_gpg_binary()
    end.

%%% @private
%%% @doc Find GPG binary in common installation locations.
%%% @returns Path to first existing GPG binary, or fallback path
%%% @end
-spec find_gpg_binary() -> string().
find_gpg_binary() ->
    Candidates = [
        %% Homebrew on Apple Silicon
        "/opt/homebrew/bin/gpg",
        %% Homebrew on Intel Mac / Linux
        "/usr/local/bin/gpg",
        %% Standard Linux
        "/usr/bin/gpg",
        %% Alternative Linux
        "/bin/gpg",
        %% Try PATH
        "gpg"
    ],
    case find_first_existing(Candidates) of
        {ok, Path} ->
            Path;
        error ->
            %% Last resort: try to find via 'which' command
            case os:find_executable("gpg") of
                %% Fallback
                false -> "/usr/bin/gpg";
                Path -> Path
            end
    end.

find_first_existing([Path | Rest]) ->
    case filelib:is_file(Path) of
        true -> {ok, Path};
        false -> find_first_existing(Rest)
    end;
find_first_existing([]) ->
    error.

%%% @doc Execute a GPG operation via port communication.
%%%
%%% This is the main entry point for GPG operations. It spawns a GPG process,
%%% sends input data, collects and parses output, and sends results back to
%%% the caller process.
%%%
%%% == Supported Operations ==
%%%
%%% <ul>
%%%   <li>`encrypt' - Encrypt plaintext for recipients</li>
%%%   <li>`decrypt' - Decrypt ciphertext</li>
%%%   <li>`import' - Import a key into the keyring</li>
%%%   <li>`verify' - Verify a clearsigned message</li>
%%%   <li>`verify_detached' - Verify a detached signature</li>
%%% </ul>
%%%
%%% == Result Format ==
%%%
%%% The caller receives a message:
%%% ```
%%% {ok, #{
%%%     stdout => Binary,           %% Main GPG output
%%%     status => [StatusMap],      %% Parsed status lines
%%%     colon => [ColonMap],        %% Parsed colon records
%%%     raw => #{...},              %% Raw unparsed lines
%%%     exit => ok | {error, {exit_status, Code}}
%%% }}
%%% '''
%%% or `{error, Result}' on failure, or `{error, timeout}'.
%%%
%%% @param Operation The operation to perform (atom)
%%% @param Data The input data (binary or tuple for verify_detached)
%%% @param Options Operation-specific options (e.g., recipient list)
%%% @param Caller The PID to send results to
%%% @returns `ok' after sending result message to caller
%%% @end
-spec run(atom(), binary(), any(), pid()) -> ok.
run(encrypt, Plain, {Recipients, Opts}, Caller) when
    is_binary(Plain), is_list(Recipients), is_list(Opts)
->
    Args = base_args(recips_arg(Recipients), Opts) ++ ["--encrypt", "--armor"],
    run_port(Args, Plain, Caller);
run(encrypt, Plain, Recipients, Caller) when
    is_binary(Plain), is_list(Recipients)
->
    %% Backwards compatibility - treat as {Recipients, []}
    run(encrypt, Plain, {Recipients, []}, Caller);
run(decrypt, Cipher, Opts, Caller) when is_binary(Cipher), is_list(Opts) ->
    Args = base_args([], Opts) ++ ["--decrypt", "--armor"],
    run_port(Args, Cipher, Caller);
run(import, KeyData, Opts, Caller) when is_binary(KeyData), is_list(Opts) ->
    Args = base_args([], Opts) ++ ["--import"],
    run_port(Args, KeyData, Caller);
run(verify, Data, Opts, Caller) when is_binary(Data), is_list(Opts) ->
    Args = base_args([], Opts) ++ ["--verify"],
    run_port(Args, Data, Caller);
run(verify_detached, {Data, Signature}, Opts, Caller) when
    is_binary(Data), is_binary(Signature), is_list(Opts)
->
    %% Write signature to a temporary file since GPG needs file input for detached sigs
    TempSig =
        "/tmp/gpg_sig_" ++
            integer_to_list(erlang:unique_integer([positive])) ++ ".sig",
    ok = file:write_file(TempSig, Signature),
    try
        Args = base_args([], Opts) ++ ["--verify", TempSig, "-"],
        run_port(Args, Data, Caller)
    after
        file:delete(TempSig)
    end;
run(list_keys, _NoData, Opts, Caller) when is_list(Opts) ->
    %% List keys doesn't need input data, use empty binary
    KeyType = proplists:get_value(key_type, Opts, public),
    Args =
        base_args([], Opts) ++
            case KeyType of
                public -> ["--list-keys"];
                secret -> ["--list-secret-keys"]
            end,
    run_port(Args, <<>>, Caller);
run(_, _, _, Caller) ->
    Caller ! {error, unsupported_operation},
    ok.

%% Run gpg with data sent via stdin
run_port(Args, InputBin, Caller) ->
    GpgBin = gpg_bin(),

    %% Write input data to a temporary file to avoid shell escaping issues
    %% and ensure clean EOF handling
    TempInput =
        "/tmp/gpg_input_" ++
            integer_to_list(erlang:unique_integer([positive])) ++ ".dat",
    ok = file:write_file(TempInput, InputBin),

    try
        ArgsStr = lists:flatten(lists:join(" ", Args)),
        %% Redirect stderr to /dev/null to discard GPG diagnostic messages
        %% Status lines will be in stdout via --status-fd=1
        ShellCmd =
            GpgBin ++ " " ++ ArgsStr ++ " < " ++ TempInput ++ " 2> /dev/null",
        Port = open_port(
            {spawn, ShellCmd},
            [binary, exit_status]
        ),
        collect(Port, Caller, #{
            stdout => [], status_lines => [], colon_lines => []
        })
    after
        file:delete(TempInput)
    end.

%%% @private
%%% @doc Build base GPG command-line arguments with options.
%%%
%%% Returns common arguments used for all GPG operations. By default includes:
%%% <ul>
%%%   <li>`--batch' - Non-interactive mode</li>
%%%   <li>`--yes' - Assume yes for prompts</li>
%%%   <li>`--status-fd=1' - Machine-readable status to stdout</li>
%%%   <li>`--with-colons' - Colon-separated output format</li>
%%% </ul>
%%%
%%% == Options ==
%%%
%%% <ul>
%%%   <li>`{trust_model, always}' - Add `--trust-model always' to bypass key trust checks</li>
%%%   <li>`{home_dir, Path}' - Use custom GPG home directory (isolated keyring)</li>
%%% </ul>
%%%
%%% @param Extra Additional arguments to append
%%% @param Opts Proplist of options to control GPG behavior
%%% @returns List of GPG command-line arguments
%%% @end
base_args(Extra, Opts) ->
    BaseArgs = ["--batch", "--yes", "--status-fd=1", "--with-colons"],

    %% Add --homedir if home_dir option is provided
    HomeDirArgs =
        case proplists:get_value(home_dir, Opts) of
            Path when is_list(Path), Path =/= "" ->
                ["--homedir", Path];
            _ ->
                []
        end,

    %% Add --trust-model if trust_model option is provided
    TrustArgs =
        case proplists:get_value(trust_model, Opts) of
            always -> ["--trust-model", "always"];
            _ -> []
        end,

    BaseArgs ++ HomeDirArgs ++ TrustArgs ++ Extra.

%%% @private
%%% @doc Build base GPG arguments without options (for backwards compatibility).
%%% Calls base_args/2 with empty options list.
%%% @end
base_args(Extra) ->
    base_args(Extra, []).

recips_arg(Recipients) ->
    lists:flatmap(fun(R) -> ["--recipient", R] end, Recipients).

%%% @private
%%% @doc Collect output from GPG port until completion or timeout.
%%%
%%% Receives data messages from the port, splits them into stdout/status/colon
%%% components, and accumulates results. When the port exits, builds the final
%%% result map and sends it to the caller.
%%%
%%% @param Port The GPG port
%%% @param Caller The PID to send results to
%%% @param Acc Accumulator map with stdout, status_lines, and colon_lines
%%% @returns `ok' after sending result to caller
%%% @end
collect(Port, Caller, Acc) ->
    receive
        {Port, {data, Data}} ->
            %% Data contains whatever gpg wrote to stdout and stderr (both come through).
            %% We need to split machine-status lines vs colon records vs regular stdout.
            Bin = iolist_to_binary(Data),
            {Std, StatusLines, ColonLines} = split_gpg_output(Bin),
            OldStdOut = maps:get(stdout, Acc),
            OldStatusLines = maps:get(status_lines, Acc),
            OldColonLines = maps:get(colon_lines, Acc),
            NewAcc = Acc#{
                stdout => [Std | OldStdOut],
                status_lines => StatusLines ++ OldStatusLines,
                colon_lines => ColonLines ++ OldColonLines
            },
            collect(Port, Caller, NewAcc);
        {Port, {exit_status, 0}} ->
            catch erlang:port_close(Port),
            Result = build_result(Acc, ok),
            Caller ! {ok, Result},
            ok;
        {Port, {exit_status, Code}} ->
            catch erlang:port_close(Port),
            Result = build_result(Acc, {error, {exit_status, Code}}),
            Caller ! {error, Result},
            ok
    after ?TIMEOUT ->
        catch erlang:port_close(Port),
        Caller ! {error, timeout},
        ok
    end.

%%% @private
%%% @doc Build the final result map from accumulated data.
%%%
%%% Reverses accumulated lists, parses status and colon lines, and constructs
%%% the structured result map.
%%%
%%% @param Acc Accumulator with raw data
%%% @param Status Exit status (ok or {error, {exit_status, Code}})
%%% @returns Result map with parsed data
%%% @end
build_result(Acc, Status) ->
    StdOut = maps:get(stdout, Acc),
    StatusLines = maps:get(status_lines, Acc),
    ColonLines = maps:get(colon_lines, Acc),
    StdBin = list_to_binary(lists:reverse(StdOut)),
    RevStatusLines = lists:reverse(StatusLines),
    RevColonLines = lists:reverse(ColonLines),
    #{
        stdout => StdBin,
        status => parse_status_lines(RevStatusLines),
        colon => parse_colon_lines(RevColonLines),
        raw => #{status_lines => RevStatusLines, colon_lines => RevColonLines},
        exit => Status
    }.

%%% @doc Split GPG output into stdout, status lines, and colon records.
%%%
%%% Parses mixed GPG output by classifying each line:
%%% <ul>
%%%   <li>Status lines start with "[GNUPG:" (from --status-fd)</li>
%%%   <li>Colon lines contain colon-separated fields (from --with-colons)</li>
%%%   <li>Everything else is regular stdout</li>
%%% </ul>
%%%
%%% == Example ==
%%%
%%% ```
%%% Output = <<"some output\n[GNUPG:] BEGIN_ENCRYPTION\npub:u:4096:1:...\n">>,
%%% {StdOut, Status, Colon} = split_gpg_output(Output),
%%% %% StdOut = <<"some output\n">>
%%% %% Status = [<<"[GNUPG:] BEGIN_ENCRYPTION">>]
%%% %% Colon = [<<"pub:u:4096:1:...">>]
%%% '''
%%%
%%% @param Bin The raw binary output from GPG
%%% @returns Tuple of `{StdoutBinary, StatusLines, ColonLines}'
%%% @end
-spec split_gpg_output(binary()) -> {binary(), [binary()], [binary()]}.
split_gpg_output(Bin) ->
    %% GNUPG status lines typically look like: "[GNUPG:] SOME_TOKEN args..."
    %% Colon records are lines with colon-separated fields; often printed to stdout/stderr.
    Lines = binary:split(Bin, <<"\n">>, [global]),
    {StdParts, Statuss, Colons} = lists:foldl(
        fun classify/2, {[], [], []}, Lines
    ),
    {
        list_to_binary(lists:reverse(StdParts)),
        lists:reverse(Statuss),
        lists:reverse(Colons)
    }.

classify(Line, {StdAcc, StatusAcc, ColonAcc}) ->
    case Line of
        %% empty line
        <<>> ->
            {StdAcc, StatusAcc, ColonAcc};
        _ ->
            %% Check if line contains "[GNUPG:" anywhere (not just at start)
            case binary:split(Line, <<"[GNUPG:">>, [global]) of
                [_SinglePart] ->
                    %% No status marker in this line
                    case is_status_line(Line) of
                        true ->
                            {StdAcc, [Line | StatusAcc], ColonAcc};
                        false ->
                            case is_colon_line(Line) of
                                true ->
                                    {StdAcc, StatusAcc, [Line | ColonAcc]};
                                false ->
                                    {
                                        [Line, <<"\n">> | StdAcc],
                                        StatusAcc,
                                        ColonAcc
                                    }
                            end
                    end;
                [BeforeFirst | StatusParts] ->
                    %% Line contains one or more status markers
                    %% BeforeFirst goes to stdout (if not empty)
                    NewStdAcc =
                        case BeforeFirst of
                            <<>> -> StdAcc;
                            _ -> [BeforeFirst | StdAcc]
                        end,
                    %% Each part in StatusParts becomes a status line
                    NewStatusLines = [
                        <<"[GNUPG:", Part/binary>>
                     || Part <- StatusParts
                    ],
                    {NewStdAcc, lists:reverse(NewStatusLines) ++ StatusAcc,
                        ColonAcc}
            end
    end.

%%% @doc Check if a line is a GPG status line.
%%%
%%% Status lines begin with the prefix "[GNUPG:" and contain machine-readable
%%% status information from GPG's --status-fd output.
%%%
%%% @param Line The line to check (binary)
%%% @returns `true' if it's a status line, `false' otherwise
%%% @end
is_status_line(<<"[GNUPG:", _/binary>>) -> true;
is_status_line(_) -> false.

%%% @doc Check if a line is a colon-separated record.
%%%
%%% Colon lines are machine-readable records from GPG's --with-colons output.
%%% They start with known record type prefixes like "pub:", "uid:", "sub:", etc.
%%%
%%% Common record types:
%%% <ul>
%%%   <li>`pub' - Public key</li>
%%%   <li>`uid' - User ID</li>
%%%   <li>`sub' - Subkey</li>
%%%   <li>`fpr' - Fingerprint</li>
%%%   <li>`sig' - Signature</li>
%%%   <li>`sec' - Secret key</li>
%%%   <li>`ssb' - Secret subkey</li>
%%%   <li>`tru' - Trust database info</li>
%%% </ul>
%%%
%%% @param Line The line to check (binary)
%%% @returns `true' if it's a colon record, `false' otherwise
%%% @end
is_colon_line(Line) ->
    %% heuristic: colon lines contain at least one ':' and typically start with a token like "pub:", "uid:", "sig:"
    case binary:match(Line, <<":">>) of
        {_, _} ->
            case binary:split(Line, <<":">>) of
                [Prefix | _] ->
                    %% tokens commonly: pub, uid, sub, tru, fpr, sig, etc.
                    lists:member(Prefix, [
                        <<"pub">>,
                        <<"uid">>,
                        <<"sub">>,
                        <<"fpr">>,
                        <<"sig">>,
                        <<"tru">>,
                        <<"sec">>,
                        <<"ssb">>
                    ]);
                _ ->
                    false
            end;
        nomatch ->
            false
    end.

%%% @doc Parse multiple status lines into structured maps.
%%%
%%% Converts a list of raw status line binaries into a list of maps,
%%% each containing a tag and arguments.
%%%
%%% @param Lines List of status line binaries
%%% @returns List of maps: `[#{tag => Binary, args => [Binary]}]'
%%% @see parse_status_line/1
%%% @end
parse_status_lines(Lines) ->
    [parse_status_line(L) || L <- Lines].

%%% @doc Parse a single GPG status line into a structured map.
%%%
%%% Status lines have the format: `[GNUPG:] TAG [ARG1 ARG2 ...]'
%%%
%%% == Example ==
%%%
%%% ```
%%% Line = <<"[GNUPG:] GOODSIG 1234ABCD Alice <alice@example.com>">>,
%%% Result = parse_status_line(Line),
%%% %% Result = #{
%%% %%   tag => <<"GOODSIG">>,
%%% %%   args => [<<"1234ABCD">>, <<"Alice">>, <<"<alice@example.com>">>]
%%% %% }
%%% '''
%%%
%%% @param Line The status line to parse (binary)
%%% @returns Map with `tag' and `args' keys
%%% @end
parse_status_line(Line) ->
    %% drop "[GNUPG:" or "[GNUPG:]" prefix and split by space
    case Line of
        <<"[GNUPG:", Rest/binary>> ->
            %% Remove leading ] and/or space if present
            Trimmed =
                case Rest of
                    <<"] ", R/binary>> -> R;
                    <<"]", R/binary>> -> R;
                    <<" ", R/binary>> -> R;
                    R -> R
                end,
            Parts = binary:split(Trimmed, <<" ">>, [global]),
            case Parts of
                [Tag | Args] -> #{tag => Tag, args => Args};
                [] -> #{tag => <<>>, args => []}
            end;
        _ ->
            #{tag => <<>>, args => []}
    end.

%%% @doc Parse multiple colon-separated records into structured maps.
%%%
%%% Converts a list of colon record binaries into a list of maps,
%%% each containing the record type and fields.
%%%
%%% @param Lines List of colon record binaries
%%% @returns List of maps: `[#{type => Binary, fields => [Binary]}]'
%%% @see parse_colon_line/1
%%% @end
parse_colon_lines(Lines) ->
    [parse_colon_line(L) || L <- Lines].

%%% @doc Parse a single colon-separated record into a structured map.
%%%
%%% Colon records have colon-separated fields where the first field
%%% indicates the record type.
%%%
%%% == Example ==
%%%
%%% ```
%%% Line = <<"pub:u:4096:1:1234ABCD:2024-01-01:::Alice <alice@example.com>">>,
%%% Result = parse_colon_line(Line),
%%% %% Result = #{
%%% %%   type => <<"pub">>,
%%% %%   fields => [<<"u">>, <<"4096">>, <<"1">>, <<"1234ABCD">>, ...]
%%% %% }
%%% '''
%%%
%%% The fields list contains all fields after the type. Field meanings depend
%%% on the record type - consult GPG documentation for --with-colons format.
%%%
%%% @param Line The colon record to parse (binary)
%%% @returns Map with `type' and `fields' keys
%%% @end
parse_colon_line(Line) ->
    Fields = binary:split(Line, <<":">>, [global]),
    %% First field is record type
    [TypeBin | Rest] = Fields,
    #{type => TypeBin, fields => Rest}.
