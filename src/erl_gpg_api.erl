%%% @doc Public API for GPG operations.
%%%
%%% This module provides a high-level interface to GPG (GNU Privacy Guard)
%%% for encryption, decryption, key management, and signature verification.
%%% All operations use asymmetric (public-key) cryptography.
%%%
%%% == Usage ==
%%%
%%% Before using this module, ensure the application is started:
%%% ```
%%% application:start(erl_gpg).
%%% '''
%%%
%%% == Key Management ==
%%%
%%% <ul>
%%%   <li>Encryption requires the recipient's public key in your keyring</li>
%%%   <li>Decryption requires your private key in your keyring</li>
%%%   <li>Signature verification requires the signer's public key</li>
%%% </ul>
%%%
%%% @end
-module(erl_gpg_api).

-export([
    encrypt/3, encrypt/4,
    decrypt/2, decrypt/3,
    import_key/2, import_key/3,
    verify/2, verify/3,
    verify_detached/3, verify_detached/4,
    list_keys/0, list_keys/1, list_keys/2,
    format_keys/1,
    compute_fingerprint/1, compute_fingerprint/2,
    get_key_info/1, get_key_info/2
]).

%% Exported for testing
-export([start_worker/3]).

%%% @private
%%% @doc Spawn a worker process to execute a GPG operation.
%%%
%%% This is an internal helper function that spawns a linked process
%%% to handle GPG port communication. The worker sends results back
%%% to the calling process.
%%%
%%% @param Operation The GPG operation to perform (encrypt, decrypt, import, verify, verify_detached)
%%% @param Payload The data to process
%%% @param Options Operation-specific options (e.g., recipient list for encryption)
%%% @returns The PID of the spawned worker process
%%% @end
start_worker(Operation, Payload, Options) ->
    Caller = self(),
    spawn_link(fun() ->
        erl_gpg_worker:run(Operation, Payload, Options, Caller)
    end).

%%% @doc Encrypt data for one or more recipients using public-key cryptography.
%%%
%%% Encrypts the provided plaintext data using the public keys of the specified
%%% recipients. Each recipient must have their public key imported into the GPG
%%% keyring before encryption.
%%%
%%% == Example ==
%%%
%%% ```
%%% Plain = <<"Hello, World!">>,
%%% Recipients = ["alice@example.com", "bob@example.com"],
%%% {ok, Result} = erl_gpg_api:encrypt(Plain, Recipients, ""),
%%% Ciphertext = maps:get(stdout, Result).
%%% '''
%%%
%%% @param Plain The plaintext data to encrypt (binary)
%%% @param Recipients List of recipient identifiers (email addresses or key IDs)
%%% @param GnupgDir GPG home directory (currently not implemented, pass empty string)
%%% @returns `{ok, Result}' where Result is a map containing encrypted data in the
%%%          `stdout' field, or `{error, Reason}' on failure
%%% @see decrypt/2
%%% @see encrypt/4
%%% @end
-spec encrypt(binary(), [string()], string()) -> {ok, map()} | {error, term()}.
encrypt(Plain, Recipients, GnupgDir) ->
    encrypt(Plain, Recipients, GnupgDir, []).

%%% @doc Encrypt data with additional options.
%%%
%%% Like encrypt/3 but accepts an options proplist for additional control.
%%%
%%% == Options ==
%%%
%%% <ul>
%%%   <li>`{trust_model, always}' - Bypass key trust checks (useful for automation)</li>
%%%   <li>`{home_dir, Path}' - Use custom GPG home directory for isolated keyring</li>
%%% </ul>
%%%
%%% == Example ==
%%%
%%% ```
%%% Plain = <<"Hello, World!">>,
%%% Recipients = ["alice@example.com"],
%%% Options = [{trust_model, always}],
%%% {ok, Result} = erl_gpg_api:encrypt(Plain, Recipients, "", Options),
%%% Ciphertext = maps:get(stdout, Result).
%%%
%%% %% Using isolated keyring
%%% IsolatedOpts = [{home_dir, "/path/to/custom/gnupg"}],
%%% {ok, Result2} = erl_gpg_api:encrypt(Plain, Recipients, "", IsolatedOpts).
%%% '''
%%%
%%% @param Plain The plaintext data to encrypt (binary)
%%% @param Recipients List of recipient identifiers (email addresses or key IDs)
%%% @param GnupgDir GPG home directory (deprecated, use `{home_dir, Path}' option instead)
%%% @param Options Proplist of options
%%% @returns `{ok, Result}' where Result is a map containing encrypted data in the
%%%          `stdout' field, or `{error, Reason}' on failure
%%% @see encrypt/3
%%% @end
-spec encrypt(binary(), [string()], string(), proplists:proplist()) ->
    {ok, map()} | {error, term()}.
encrypt(Plain, Recipients, _GnupgDir, Options) when
    is_binary(Plain), is_list(Recipients)
->
    start_worker(encrypt, Plain, {Recipients, Options}),
    receive
        {ok, Result} -> {ok, Result};
        {error, E} -> {error, E}
    after 20000 -> {error, timeout}
    end.

%%% @doc Decrypt ciphertext using your private key.
%%%
%%% Decrypts data that was encrypted for your public key. Your corresponding
%%% private key must be present in the GPG keyring. If the private key is
%%% passphrase-protected, ensure gpg-agent is configured or use a passphrase-less key.
%%%
%%% == Example ==
%%%
%%% ```
%%% {ok, Result} = erl_gpg_api:decrypt(Ciphertext, ""),
%%% Plaintext = maps:get(stdout, Result),
%%% case maps:get(exit, Result) of
%%%     ok -> io:format("Success~n");
%%%     {error, _} -> io:format("Failed~n")
%%% end.
%%% '''
%%%
%%% @param Cipher The encrypted data to decrypt (binary, typically ASCII-armored)
%%% @param GnupgDir GPG home directory (currently not implemented, pass empty string)
%%% @returns `{ok, Result}' where Result is a map containing decrypted data in the
%%%          `stdout' field, or `{error, Reason}' on failure
%%% @see encrypt/3
%%% @see decrypt/3
%%% @end
-spec decrypt(binary(), string()) -> {ok, map()} | {error, term()}.
decrypt(Cipher, GnupgDir) ->
    decrypt(Cipher, GnupgDir, []).

%%% @doc Decrypt ciphertext with additional options.
%%%
%%% Like decrypt/2 but accepts an options proplist.
%%%
%%% @param Cipher The encrypted data to decrypt (binary, typically ASCII-armored)
%%% @param GnupgDir GPG home directory (currently not implemented, pass empty string)
%%% @param Options Proplist of options
%%% @returns `{ok, Result}' where Result is a map containing decrypted data
%%% @see decrypt/2
%%% @end
-spec decrypt(binary(), string(), proplists:proplist()) ->
    {ok, map()} | {error, term()}.
decrypt(Cipher, _GnupgDir, Options) when is_binary(Cipher) ->
    start_worker(decrypt, Cipher, Options),
    receive
        {ok, Result} -> {ok, Result};
        {error, E} -> {error, E}
    after 20000 -> {error, timeout}
    end.

%%% @doc Import a public or private key into the GPG keyring.
%%%
%%% Imports PGP key data (public or private) into the keyring. Public keys
%%% must be imported before you can encrypt for a recipient. Private keys
%%% must be imported before you can decrypt messages encrypted for that key.
%%%
%%% == Example ==
%%%
%%% ```
%%% PublicKey = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
%%% {ok, Result} = erl_gpg_api:import_key(PublicKey, ""),
%%% StatusLines = maps:get(status, Result),
%%% %% Check for IMPORT_OK status tag
%%% '''
%%%
%%% @param KeyData The PGP key data to import (binary, ASCII-armored format)
%%% @param GnupgDir GPG home directory (currently not implemented, pass empty string)
%%% @returns `{ok, Result}' where Result contains import status information,
%%%          or `{error, Reason}' on failure
%%% @see import_key/3
%%% @end
-spec import_key(binary(), string()) -> {ok, map()} | {error, term()}.
import_key(KeyData, GnupgDir) ->
    import_key(KeyData, GnupgDir, []).

%%% @doc Import a key with additional options.
%%%
%%% Like import_key/2 but accepts an options proplist.
%%%
%%% @param KeyData The PGP key data to import (binary, ASCII-armored format)
%%% @param GnupgDir GPG home directory (currently not implemented, pass empty string)
%%% @param Options Proplist of options
%%% @returns `{ok, Result}' where Result contains import status information
%%% @see import_key/2
%%% @end
-spec import_key(binary(), string(), proplists:proplist()) ->
    {ok, map()} | {error, term()}.
import_key(KeyData, _GnupgDir, Options) when is_binary(KeyData) ->
    start_worker(import, KeyData, Options),
    receive
        {ok, Result} -> {ok, Result};
        {error, E} -> {error, E}
    after 20000 -> {error, timeout}
    end.

%%% @doc Verify a clearsigned message.
%%%
%%% Verifies a PGP clearsigned message where the signature is embedded with
%%% the signed data. The signer's public key must be in the keyring.
%%%
%%% == Example ==
%%%
%%% ```
%%% SignedData = <<"-----BEGIN PGP SIGNED MESSAGE-----
%%% Hash: SHA256
%%%
%%% Message content here
%%% -----BEGIN PGP SIGNATURE-----
%%% ...
%%% -----END PGP SIGNATURE-----">>,
%%% {ok, Result} = erl_gpg_api:verify(SignedData, ""),
%%% Status = maps:get(status, Result),
%%% IsGood = lists:any(fun(#{tag := Tag}) -> Tag =:= <<"GOODSIG">> end, Status).
%%% '''
%%%
%%% @param Data The clearsigned message data (binary)
%%% @param GnupgDir GPG home directory (currently not implemented, pass empty string)
%%% @returns `{ok, Result}' where Result contains verification status in the
%%%          `status' field (look for GOODSIG, BADSIG, or ERRSIG tags),
%%%          or `{error, Reason}' on failure
%%% @see verify_detached/3
%%% @see verify/3
%%% @end
-spec verify(binary(), string()) -> {ok, map()} | {error, term()}.
verify(Data, GnupgDir) ->
    verify(Data, GnupgDir, []).

%%% @doc Verify a clearsigned message with additional options.
%%%
%%% Like verify/2 but accepts an options proplist.
%%%
%%% @param Data The clearsigned message data (binary)
%%% @param GnupgDir GPG home directory (currently not implemented, pass empty string)
%%% @param Options Proplist of options
%%% @returns `{ok, Result}' where Result contains verification status
%%% @see verify/2
%%% @end
-spec verify(binary(), string(), proplists:proplist()) ->
    {ok, map()} | {error, term()}.
verify(Data, _GnupgDir, Options) when is_binary(Data) ->
    start_worker(verify, Data, Options),
    receive
        {ok, Result} -> {ok, Result};
        {error, E} -> {error, E}
    after 20000 -> {error, timeout}
    end.

%%% @doc Verify a detached signature against data.
%%%
%%% Verifies a detached PGP signature against the original data. This is commonly
%%% used for verifying signed documents like CSRs (Certificate Signing Requests)
%%% where the signature is stored separately from the data.
%%%
%%% The signer's public key must be imported into the keyring before verification.
%%%
%%% == Example ==
%%%
%%% ```
%%% %% CSR verification workflow
%%% CSRData = <<"-----BEGIN CERTIFICATE REQUEST-----\n...">>,
%%% SignatureData = <<"-----BEGIN PGP SIGNATURE-----\n...">>,
%%%
%%% %% 1. Import signer's public key (if not already imported)
%%% {ok, _} = erl_gpg_api:import_key(PublicKey, ""),
%%%
%%% %% 2. Verify the signature
%%% {ok, Result} = erl_gpg_api:verify_detached(CSRData, SignatureData, ""),
%%%
%%% %% 3. Check the verification status
%%% Status = maps:get(status, Result),
%%% case lists:any(fun(#{tag := Tag}) -> Tag =:= <<"GOODSIG">> end, Status) of
%%%     true ->
%%%         %% Extract signer information
%%%         [#{args := [_KeyID, SignerName | _]} | _] =
%%%             lists:filter(fun(#{tag := T}) -> T =:= <<"GOODSIG">> end, Status),
%%%         {ok, SignerName};
%%%     false ->
%%%         {error, invalid_signature}
%%% end.
%%% '''
%%%
%%% == Status Tags ==
%%%
%%% <ul>
%%%   <li>`GOODSIG' - Signature is valid, key is in keyring</li>
%%%   <li>`BADSIG' - Signature verification failed (data tampered)</li>
%%%   <li>`ERRSIG' - Error during verification (e.g., missing public key)</li>
%%%   <li>`VALIDSIG' - Additional validation info (fingerprint, timestamp)</li>
%%%   <li>`TRUST_ULTIMATE' / `TRUST_FULL' - Trust level of signing key</li>
%%% </ul>
%%%
%%% @param Data The original data that was signed (binary)
%%% @param Signature The detached signature (binary, ASCII-armored)
%%% @param GnupgDir GPG home directory (currently not implemented, pass empty string)
%%% @returns `{ok, Result}' where Result contains verification status in the
%%%          `status' field, or `{error, Reason}' on failure
%%% @see verify/2
%%% @see verify_detached/4
%%% @end
-spec verify_detached(binary(), binary(), string()) ->
    {ok, map()} | {error, term()}.
verify_detached(Data, Signature, GnupgDir) ->
    verify_detached(Data, Signature, GnupgDir, []).

%%% @doc Verify a detached signature with additional options.
%%%
%%% Like verify_detached/3 but accepts an options proplist.
%%%
%%% @param Data The original data that was signed (binary)
%%% @param Signature The detached signature (binary, ASCII-armored)
%%% @param GnupgDir GPG home directory (currently not implemented, pass empty string)
%%% @param Options Proplist of options
%%% @returns `{ok, Result}' where Result contains verification status
%%% @see verify_detached/3
%%% @end
-spec verify_detached(binary(), binary(), string(), proplists:proplist()) ->
    {ok, map()} | {error, term()}.
verify_detached(Data, Signature, _GnupgDir, Options) when
    is_binary(Data), is_binary(Signature)
->
    start_worker(verify_detached, {Data, Signature}, Options),
    receive
        {ok, Result} -> {ok, Result};
        {error, E} -> {error, E}
    after 20000 -> {error, timeout}
    end.

%%% @doc List all public keys in the keyring.
%%%
%%% Returns a structured data representation of all public keys in the GPG keyring.
%%% The result includes parsed colon-separated records for each key, subkey, user ID,
%%% fingerprint, and signature.
%%%
%%% == Example ==
%%%
%%% ```
%%% {ok, Result} = erl_gpg_api:list_keys(),
%%% Keys = parse_key_list(maps:get(colon, Result)),
%%% %% Keys is a list of key records from --with-colons output
%%% '''
%%%
%%% @returns `{ok, Result}' where Result is a map containing parsed key data in the
%%%          `colon' field, or `{error, Reason}' on failure
%%% @see list_keys/1
%%% @see list_keys/2
%%% @see format_keys/1
%%% @end
-spec list_keys() -> {ok, map()} | {error, term()}.
list_keys() ->
    list_keys("", []).

%%% @doc List keys in the keyring with options.
%%%
%%% Like list_keys/0 but accepts an options proplist.
%%%
%%% == Options ==
%%%
%%% <ul>
%%%   <li>`{key_type, public}' - List public keys (default)</li>
%%%   <li>`{key_type, secret}' - List secret (private) keys</li>
%%% </ul>
%%%
%%% == Example ==
%%%
%%% ```
%%% %% List secret keys
%%% {ok, Result} = erl_gpg_api:list_keys([{key_type, secret}]),
%%% SecretKeys = parse_key_list(maps:get(colon, Result)).
%%% '''
%%%
%%% @param Options Proplist of options
%%% @returns `{ok, Result}' where Result contains key data
%%% @see list_keys/0
%%% @see list_keys/2
%%% @end
-spec list_keys(proplists:proplist()) -> {ok, map()} | {error, term()}.
list_keys(Options) when is_list(Options) ->
    list_keys("", Options).

%%% @doc List keys with GPG home directory and options.
%%%
%%% Like list_keys/1 but also accepts a GPG home directory parameter.
%%%
%%% @param GnupgDir GPG home directory (currently not implemented, pass empty string)
%%% @param Options Proplist of options
%%% @returns `{ok, Result}' where Result contains key data
%%% @see list_keys/0
%%% @see list_keys/1
%%% @end
-spec list_keys(string(), proplists:proplist()) ->
    {ok, map()} | {error, term()}.
list_keys(_GnupgDir, Options) ->
    start_worker(list_keys, <<>>, Options),
    receive
        {ok, Result} -> {ok, Result};
        {error, E} -> {error, E}
    after 20000 -> {error, timeout}
    end.

%%% @doc Format key list data into a human-readable string.
%%%
%%% Takes the result from list_keys and formats it into a pretty-printed
%%% string suitable for display. Shows key IDs, types, creation dates,
%%% user IDs, and fingerprints.
%%%
%%% == Example ==
%%%
%%% ```
%%% {ok, Result} = erl_gpg_api:list_keys(),
%%% FormattedOutput = erl_gpg_api:format_keys(Result),
%%% io:format("~s", [FormattedOutput]).
%%% '''
%%%
%%% Output format:
%%% ```
%%% Public Keys:
%%% ------------
%%% pub  rsa4096/1234ABCD  2024-01-01
%%%      Alice <alice@example.com>
%%%      Fingerprint: 1234 5678 90AB CDEF ...
%%%
%%% pub  rsa2048/5678EFGH  2024-02-15
%%%      Bob <bob@example.com>
%%%      Fingerprint: ABCD EF12 3456 7890 ...
%%% '''
%%%
%%% @param Result The result map from list_keys containing parsed colon data
%%% @returns Formatted string representation of the keys
%%% @see list_keys/0
%%% @end
-spec format_keys(map()) -> iolist().
format_keys(Result) ->
    ColonData = maps:get(colon, Result, []),
    %% Reverse the colon data since it comes in reverse order from GPG output parsing
    ReversedData = lists:reverse(ColonData),
    KeyType =
        case maps:get(exit, Result, ok) of
            ok ->
                %% Check if this looks like secret keys based on first record (after reversal)
                case ReversedData of
                    [#{type := <<"sec">>} | _] -> "Secret";
                    _ -> "Public"
                end;
            _ ->
                "Public"
        end,
    Header = io_lib:format("~s Keys:~n~s~n", [
        KeyType, lists:duplicate(length(KeyType) + 6, $-)
    ]),
    KeysFormatted = format_key_records(ReversedData, []),
    [Header, KeysFormatted].

%%% @doc Compute fingerprint from a public key.
%%%
%%% Imports the key temporarily and extracts its fingerprint. This is useful
%%% for verifying key identity without needing to parse the key format manually.
%%%
%%% == Example ==
%%%
%%% ```
%%% PublicKey = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
%%% {ok, Fingerprint} = erl_gpg_api:compute_fingerprint(PublicKey),
%%% %% Fingerprint is a binary like <<"1234567890ABCDEF1234567890ABCDEF12345678">>
%%% '''
%%%
%%% @param KeyData The PGP public key (binary, ASCII-armored format)
%%% @returns `{ok, Fingerprint}' where Fingerprint is a 40-character hex binary,
%%%          or `{error, Reason}' on failure
%%% @end
-spec compute_fingerprint(binary()) -> {ok, binary()} | {error, term()}.
compute_fingerprint(KeyData) ->
    compute_fingerprint(KeyData, "").

%%% @doc Compute fingerprint from a public key with GPG home directory.
%%%
%%% @param KeyData The PGP public key (binary, ASCII-armored format)
%%% @param GnupgDir GPG home directory (currently not implemented, pass empty string)
%%% @returns `{ok, Fingerprint}' where Fingerprint is a 40-character hex binary
%%% @see compute_fingerprint/1
%%% @end
-spec compute_fingerprint(binary(), string()) ->
    {ok, binary()} | {error, term()}.
compute_fingerprint(KeyData, _GnupgDir) when is_binary(KeyData) ->
    %% Use show-only import to get fingerprint without actually importing
    %% This avoids interference with keys already in the keyring
    Options = [{import_options, "show-only"}],
    start_worker(import, KeyData, Options),
    receive
        {ok, Result} ->
            %% Parse colon data to extract fingerprint from the imported key
            ColonData = maps:get(colon, Result, []),
            case extract_fingerprint_from_colon(ColonData) of
                {ok, FP} -> {ok, FP};
                error -> {error, fingerprint_not_found}
            end;
        {error, E} ->
            {error, E}
    after 20000 ->
        {error, timeout}
    end.

%%% @doc Get comprehensive key information from a public key block.
%%%
%%% Imports the key and extracts useful metadata including fingerprint,
%%% key ID, creation date, and user IDs.
%%%
%%% == Example ==
%%%
%%% ```
%%% PublicKey = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
%%% {ok, KeyInfo} = erl_gpg_api:get_key_info(PublicKey),
%%% Fingerprint = maps:get(fingerprint, KeyInfo),
%%% KeyID = maps:get(key_id, KeyInfo),
%%% UserIDs = maps:get(user_ids, KeyInfo).
%%% '''
%%%
%%% @param KeyData The PGP public key (binary, ASCII-armored format)
%%% @returns `{ok, KeyInfo}' where KeyInfo is a map with keys:
%%%          - `fingerprint' - 40-char hex binary
%%%          - `key_id' - Short key ID binary
%%%          - `algorithm' - Key algorithm binary (e.g., <<"rsa4096">>)
%%%          - `creation_date' - Unix timestamp (integer)
%%%          - `user_ids' - List of user ID binaries
%%%          or `{error, Reason}' on failure
%%% @end
-spec get_key_info(binary()) -> {ok, map()} | {error, term()}.
get_key_info(KeyData) ->
    get_key_info(KeyData, "").

%%% @doc Get key information with GPG home directory.
%%%
%%% @param KeyData The PGP public key (binary, ASCII-armored format)
%%% @param GnupgDir GPG home directory (currently not implemented, pass empty string)
%%% @returns `{ok, KeyInfo}' map with key metadata
%%% @see get_key_info/1
%%% @end
-spec get_key_info(binary(), string()) -> {ok, map()} | {error, term()}.
get_key_info(KeyData, _GnupgDir) when is_binary(KeyData) ->
    %% Use show-only import to parse the key without adding it to the keyring
    %% This avoids interference with keys already in the keyring
    Options = [{import_options, "show-only"}],
    start_worker(import, KeyData, Options),
    receive
        {ok, Result} ->
            %% Parse colon data to extract key info from the provided key only
            ColonData = maps:get(colon, Result, []),
            case parse_key_info_from_colon(lists:reverse(ColonData)) of
                {ok, KeyInfo} -> {ok, KeyInfo};
                error -> {error, key_info_not_found}
            end;
        {error, E} ->
            {error, E}
    after 20000 ->
        {error, timeout}
    end.

%%% @private
%%% @doc Format individual key records from colon-separated data.
%%%
%%% Processes colon records and formats them into readable output.
%%% Groups records by key (pub/sec) and includes associated UIDs and fingerprints.
%%%
%%% @param Records List of parsed colon records
%%% @param Acc Accumulator for formatted output
%%% @returns Formatted iolist
%%% @end
format_key_records([], Acc) ->
    lists:reverse(Acc);
format_key_records([Record | Rest], Acc) ->
    case Record of
        #{type := Type, fields := Fields} when
            Type =:= <<"pub">>; Type =:= <<"sec">>
        ->
            %% Public or secret key record
            %% Fields: [validity, key_length, algo, key_id, creation_date, expiry, ...]
            {KeyInfo, UIDsAndMore, Remaining} = collect_key_info(
                Type, Fields, Rest
            ),
            FormattedKey = format_single_key(Type, KeyInfo, UIDsAndMore),
            format_key_records(Remaining, [FormattedKey, "\n" | Acc]);
        _ ->
            %% Skip other record types at top level (they'll be handled in context)
            format_key_records(Rest, Acc)
    end.

%%% @private
%%% @doc Collect all records associated with a key (UIDs, fingerprints, subkeys).
%%%
%%% @param Type Key type (pub or sec)
%%% @param Fields Key record fields
%%% @param Rest Remaining records
%%% @returns Tuple of {KeyInfo, AssociatedRecords, RemainingRecords}
%%% @end
collect_key_info(Type, Fields, Rest) ->
    %% Extract key info from fields
    %% Fields: [validity, key_length, algo, key_id, creation_date, expiry_date, ..., ..., ..., ..., capabilities, ...]
    [Validity, KeyLength, Algo, KeyID, CreationDate, ExpiryDate | _RestFields] =
        %% Pad with empty fields
        Fields ++ lists:duplicate(20, <<>>),

    %% Capabilities are typically at index 11 (12th field)
    Capabilities =
        case length(Fields) >= 11 of
            true -> lists:nth(11, Fields);
            false -> <<>>
        end,

    KeyInfo = #{
        type => Type,
        validity => Validity,
        key_length => KeyLength,
        algo => Algo,
        key_id => KeyID,
        creation_date => CreationDate,
        expiry_date => ExpiryDate,
        capabilities => Capabilities
    },
    %% Collect associated records (uid, fpr, sub) until next pub/sec
    {Associated, Remaining} = collect_associated(Rest, []),
    {KeyInfo, Associated, Remaining}.

%%% @private
%%% @doc Collect records associated with current key until next key starts.
%%% @end
collect_associated([], Acc) ->
    {lists:reverse(Acc), []};
collect_associated([Record = #{type := Type} | Rest], Acc) ->
    case Type of
        T when T =:= <<"pub">>; T =:= <<"sec">> ->
            %% Next key started, stop collecting
            {lists:reverse(Acc), [Record | Rest]};
        _ ->
            %% Part of current key, keep collecting
            collect_associated(Rest, [Record | Acc])
    end.

%%% @private
%%% @doc Format a single key with its associated UIDs and fingerprints.
%%% @end
format_single_key(Type, KeyInfo, Associated) ->
    #{
        key_length := KeyLen,
        algo := Algo,
        key_id := KeyID,
        creation_date := CreationDate,
        expiry_date := ExpiryDate,
        validity := Validity,
        capabilities := Capabilities
    } = KeyInfo,

    %% Format algorithm number to name
    AlgoName = format_algo(Algo),

    %% Format creation date (Unix timestamp to date)
    DateStr = format_date(CreationDate),

    %% Format expiry info
    ExpiryStr =
        case ExpiryDate of
            <<>> -> "";
            _ -> " [expires: " ++ format_date(ExpiryDate) ++ "]"
        end,

    %% Format validity
    ValidityStr = format_validity(Validity),

    %% Format capabilities
    CapStr =
        case Capabilities of
            <<>> -> "";
            _ -> " [" ++ format_capabilities(Capabilities) ++ "]"
        end,

    %% Main key line
    KeyLine = io_lib:format(
        "~s  ~s~s/~s  ~s~s~s~s~n",
        [
            Type,
            AlgoName,
            KeyLen,
            format_key_id(KeyID),
            DateStr,
            ExpiryStr,
            ValidityStr,
            CapStr
        ]
    ),

    %% Format associated UIDs and fingerprints
    UIDLines = format_associated(Associated),

    [KeyLine, UIDLines].

%%% @private
%%% @doc Format associated records (UIDs, fingerprints, subkeys).
%%% @end
format_associated(Records) ->
    lists:map(
        fun(Record) ->
            case Record of
                #{type := <<"uid">>, fields := Fields} ->
                    %% UID record - Fields: [validity, ..., ..., ..., ..., ..., ..., ..., ..., uid_string]
                    %% The UID is at index 9 (10th field, 1-based)
                    UID =
                        case length(Fields) >= 9 of
                            true -> lists:nth(9, Fields);
                            false -> <<>>
                        end,
                    case UID of
                        <<>> -> [];
                        _ -> io_lib:format("     ~s~n", [UID])
                    end;
                #{type := <<"fpr">>, fields := Fields} ->
                    %% Fingerprint - Fields: [..., ..., ..., ..., ..., ..., ..., ..., ..., fingerprint]
                    %% The fingerprint is at index 9 (10th field, 1-based)
                    FPR =
                        case length(Fields) >= 9 of
                            true -> lists:nth(9, Fields);
                            false -> <<>>
                        end,
                    case FPR of
                        <<>> ->
                            [];
                        _ ->
                            io_lib:format("     Fingerprint: ~s~n", [
                                format_fingerprint(FPR)
                            ])
                    end;
                #{type := <<"sub">>, fields := Fields} ->
                    %% Subkey - Fields: [validity, key_length, algo, key_id, ...]
                    [_Validity, KeyLen, Algo, KeyID | _] =
                        Fields ++ lists:duplicate(10, <<>>),
                    AlgoName = format_algo(Algo),
                    io_lib:format(
                        "     sub  ~s~s/~s~n",
                        [AlgoName, KeyLen, format_key_id(KeyID)]
                    );
                _ ->
                    []
            end
        end,
        Records
    ).

%%% @private
%%% @doc Format algorithm number to readable name.
%%% @end
format_algo(<<"1">>) -> "rsa";
format_algo(<<"17">>) -> "dsa";
format_algo(<<"18">>) -> "ecdh";
format_algo(<<"19">>) -> "ecdsa";
format_algo(<<"22">>) -> "eddsa";
format_algo(Other) -> binary_to_list(Other).

%%% @private
%%% @doc Format key ID (take last 8 characters for short form).
%%% @end
format_key_id(KeyID) when byte_size(KeyID) > 8 ->
    binary:part(KeyID, byte_size(KeyID) - 8, 8);
format_key_id(KeyID) ->
    KeyID.

%%% @private
%%% @doc Format fingerprint with spaces every 4 characters.
%%% @end
format_fingerprint(FPR) ->
    List = binary_to_list(FPR),
    format_fingerprint_spaces(List, []).

format_fingerprint_spaces([], Acc) ->
    lists:reverse(Acc);
format_fingerprint_spaces([A, B, C, D | Rest], Acc) ->
    format_fingerprint_spaces(Rest, [$\s, D, C, B, A | Acc]);
format_fingerprint_spaces(Remainder, Acc) ->
    lists:reverse(Acc) ++ Remainder.

%%% @private
%%% @doc Format Unix timestamp to readable date.
%%% @end
format_date(<<>>) ->
    "";
format_date(Timestamp) when is_binary(Timestamp) ->
    try
        Secs = binary_to_integer(Timestamp),
        {{Y, M, D}, _} = calendar:gregorian_seconds_to_datetime(
            %% Unix epoch offset
            Secs + 62167219200
        ),
        io_lib:format("~4..0w-~2..0w-~2..0w", [Y, M, D])
    catch
        _:_ -> binary_to_list(Timestamp)
    end;
format_date(_) ->
    "".

%%% @private
%%% @doc Format validity field to human-readable string.
%%% @end
format_validity(<<"u">>) -> " [ultimate]";
format_validity(<<"f">>) -> " [full]";
format_validity(<<"m">>) -> " [marginal]";
format_validity(<<"n">>) -> " [never]";
format_validity(<<"-">>) -> " [unknown]";
format_validity(<<"q">>) -> " [undefined]";
format_validity(<<"i">>) -> " [invalid]";
format_validity(<<"r">>) -> " [revoked]";
format_validity(<<"e">>) -> " [expired]";
format_validity(_) -> "".

%%% @private
%%% @doc Format capabilities field to human-readable string.
%%% Capabilities: e=encrypt, s=sign, c=certify, a=authenticate, E=group encryption
%%% @end
format_capabilities(Caps) when is_binary(Caps) ->
    format_capabilities(binary_to_list(Caps));
format_capabilities(Caps) when is_list(Caps) ->
    CapList = lists:filtermap(
        fun(C) ->
            case C of
                $e -> {true, "encrypt"};
                $s -> {true, "sign"};
                $c -> {true, "certify"};
                $a -> {true, "auth"};
                $E -> {true, "group-encrypt"};
                $S -> {true, "Sign"};
                $C -> {true, "Certify"};
                $A -> {true, "Auth"};
                _ -> false
            end
        end,
        Caps
    ),
    string:join(CapList, ", ");
format_capabilities(_) ->
    "".

%%% @private
%%% @doc Extract fingerprint from colon-formatted GPG output.
%%%
%%% Searches for the first 'fpr' (fingerprint) record and returns the fingerprint.
%%% The fingerprint is in field 10 (index 9 in 0-based indexing, field 10 in 1-based).
%%%
%%% @param ColonData List of parsed colon records (already reversed)
%%% @returns {ok, Fingerprint} or error
%%% @end
extract_fingerprint_from_colon([]) ->
    error;
extract_fingerprint_from_colon([#{type := <<"fpr">>, fields := Fields} | _]) ->
    %% Fingerprint is in field 9 (lists are 1-indexed in Erlang)
    case length(Fields) >= 9 of
        true ->
            case lists:nth(9, Fields) of
                <<>> -> error;
                FP -> {ok, FP}
            end;
        false ->
            error
    end;
extract_fingerprint_from_colon([_ | Rest]) ->
    extract_fingerprint_from_colon(Rest).

%%% @private
%%% @doc Parse comprehensive key information from colon-formatted GPG output.
%%%
%%% Extracts fingerprint, key ID, algorithm, creation date, and user IDs from
%%% the colon-formatted output of `gpg --list-keys --with-colons`.
%%%
%%% @param ColonData List of parsed colon records (already reversed)
%%% @returns {ok, KeyInfo} map or error
%%% @end
parse_key_info_from_colon(ColonData) ->
    parse_key_info_from_colon(ColonData, #{
        fingerprint => undefined,
        key_id => undefined,
        algorithm => undefined,
        creation_date => undefined,
        user_ids => []
    }).

parse_key_info_from_colon([], Acc) ->
    case maps:get(fingerprint, Acc) of
        undefined -> error;
        _ -> {ok, Acc}
    end;
parse_key_info_from_colon([#{type := <<"pub">>, fields := Fields} | Rest], Acc) ->
    %% pub record: fields are [type, validity, key_length, algo, key_id, creation, expiry, ...]
    %% Field indices (1-based): 3=key_length, 4=algo, 5=key_id, 6=creation
    KeyID = safe_nth(5, Fields, <<>>),
    Algo = safe_nth(4, Fields, <<>>),
    KeyLen = safe_nth(3, Fields, <<>>),
    Algorithm = <<Algo/binary, KeyLen/binary>>,
    CreationStr = safe_nth(6, Fields, <<"0">>),
    CreationDate =
        try
            binary_to_integer(CreationStr)
        catch
            _:_ -> 0
        end,
    parse_key_info_from_colon(Rest, Acc#{
        key_id => KeyID,
        algorithm => Algorithm,
        creation_date => CreationDate
    });
parse_key_info_from_colon([#{type := <<"fpr">>, fields := Fields} | Rest], Acc) ->
    %% fpr record: fingerprint is in field 10
    FP = safe_nth(10, Fields, <<>>),
    parse_key_info_from_colon(Rest, Acc#{fingerprint => FP});
parse_key_info_from_colon([#{type := <<"uid">>, fields := Fields} | Rest], Acc) ->
    %% uid record: user ID is in field 9 (not 10 as documentation suggests)
    UID = safe_nth(9, Fields, <<>>),
    UserIDs = maps:get(user_ids, Acc, []),
    parse_key_info_from_colon(Rest, Acc#{user_ids => [UID | UserIDs]});
parse_key_info_from_colon([_ | Rest], Acc) ->
    parse_key_info_from_colon(Rest, Acc).

%%% @private
%%% @doc Safely get the Nth element from a list, returning a default if out of bounds.
%%% @end
safe_nth(N, List, Default) when is_integer(N), is_list(List) ->
    case N > 0 andalso N =< length(List) of
        true -> lists:nth(N, List);
        false -> Default
    end.
