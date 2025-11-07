# erl_gpg - Erlang interface to GPG

An Erlang interface to GPG (GNU Privacy Guard) using ports for secure
encryption, decryption, key management, and signature verification.

## Features

- **Encryption/Decryption**: Encrypt and decrypt data using GPG
- **Key Management**: Import and list public/private keys
- **Signature Verification**: Verify GPG signatures (clearsigned and detached)
- **Key Listing**: List keys with structured data and pretty-print formatting
- **Structured Output**: Parse GPG's machine-readable output (status-fd and --with-colons)
- **Dynamic GPG Binary Detection**: Automatically locates GPG on your system
- **Trust Model Options**: Bypass key trust checks when needed
- **Isolated Keyrings**: Use custom GPG home directories via `{home_dir, Path}` option
- **Comprehensive Testing**: Full EUnit test suite

## Documentation

**[Complete API Documentation](https://etnt.github.io/erl_gpg/)** - Comprehensive EDoc-generated documentation

For local documentation generation:
```bash
rebar3 ex_doc
# Open doc/index.html in your browser
```

## Architecture

- `erl_gpg_api` - Public synchronous API for GPG operations
- `erl_gpg_worker` - Worker module that manages GPG port communication and output parsing
- `erl_gpg_sup` - OTP supervisor
- `erl_gpg_app` - OTP application behavior

## Building

Build with rebar3:

```bash
rebar3 compile
```

## Usage

### Starting the Application

```erlang
application:start(erl_gpg).
```

### Public/Private Key Cryptography

This library uses GPG's **asymmetric (public-key) encryption**:

- **Encryption** uses the recipient's **PUBLIC key** to encrypt data
  - GPG looks up the public key by email/key ID in your GPG keyring
  - You must import the recipient's public key first (see "Importing a Key" below)
  - Multiple recipients can be specified - GPG encrypts so any of them can decrypt

- **Decryption** uses **YOUR PRIVATE key** to decrypt data
  - The encrypted data must have been encrypted for your public key
  - GPG automatically finds the matching private key in your keyring
  - You'll be prompted for the passphrase if your private key is protected

### Encrypting Data

```erlang
%% First, ensure the recipient's public key is in your GPG keyring
%% (See "Listing Keys" and "Importing a Key" sections below)

Plain = <<"Hello, World!">>,
Recipients = ["user@example.com"],  %% Email or Key ID
{ok, Result} = erl_gpg_api:encrypt(Plain, Recipients, "").

%% Access the encrypted data (ASCII-armored)
Ciphertext = maps:get(stdout, Result).

%% Can encrypt for multiple recipients
MultipleRecipients = ["alice@example.com", "bob@example.com"],
{ok, Result2} = erl_gpg_api:encrypt(Plain, MultipleRecipients, "").
```

#### Encrypting with Trust Options

If GPG refuses to encrypt due to untrusted keys, use the trust_model option:

```erlang
Plain = <<"Hello, World!">>,
Recipients = ["user@example.com"],
Options = [{trust_model, always}],  %% Bypass trust checks
{ok, Result} = erl_gpg_api:encrypt(Plain, Recipients, "", Options).
```

### Decrypting Data

```erlang
%% Requires YOUR private key to be in the GPG keyring
%% (the one matching the public key used for encryption)

{ok, Result} = erl_gpg_api:decrypt(Ciphertext, "").
Plaintext = maps:get(stdout, Result).

%% Check decryption status
case maps:get(exit, Result) of
    ok -> io:format("Decryption successful~n");
    {error, _} -> io:format("Decryption failed~n")
end.
```

### Importing a Key

Import a public key (for encrypting TO someone) or private key (for decrypting):

```erlang
%% Import someone's public key to encrypt messages to them
PublicKeyData = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
{ok, Result} = erl_gpg_api:import_key(PublicKeyData, "").

%% Check import status
StatusLines = maps:get(status, Result),
%% Look for IMPORT_OK status

%% Import your own private key to decrypt messages
PrivateKeyData = <<"-----BEGIN PGP PRIVATE KEY BLOCK-----\n...">>,
{ok, Result2} = erl_gpg_api:import_key(PrivateKeyData, "").
```

### Listing Keys

List all keys in your GPG keyring with structured data or pretty-printed output:

```erlang
%% Get structured key data
{ok, Result} = erl_gpg_api:list_keys().

%% Pretty print the keys
io:format("~s", [erl_gpg_api:format_keys(Result)]).

%% Example output:
%% Public Keys:
%% ------------
%%
%% pub  eddsa255/8EAC160D  2025-09-20 [expires: 2028-09-20] [ultimate] [sign, certify, encrypt]
%%      Alice Smith <alice.smith@example.com>
%%      Fingerprint: D783 F534 29F3 0D02 0C23 E6B8 1000 88AF 8E2C 16DD
%%      sub  ecdh255/63FC744A
%%
%% pub  eddsa255/189497DE  2025-10-20 [expires: 2028-10-20] [unknown] [sign, certify, encrypt]
%%      Bob Brown <bob.brown@example.com>
%%      Fingerprint: 9670 FE3F BB22 2A56 AAE9 F5B9 8133 8C76 1894 12DE
%%      sub  ecdh255/0C91F328
```

#### Listing Secret (Private) Keys

```erlang
%% List secret keys
{ok, Result} = erl_gpg_api:list_keys([{key_type, secret}]).
io:format("~s", [erl_gpg_api:format_keys(Result)]).
```

#### Programmatically Extracting Key Information

```erlang
%% Get key data as structured maps
{ok, Result} = erl_gpg_api:list_keys().
ColonData = maps:get(colon, Result),

%% Extract emails and key IDs
lists:foreach(fun(Record) ->
    case Record of
        #{type := <<"pub">>, fields := Fields} ->
            [_Validity, _KeyLen, _Algo, KeyID | _] = Fields,
            io:format("Public key ID: ~s~n", [KeyID]);
        #{type := <<"uid">>, fields := Fields} ->
            %% User ID is at index 9 (field 8, 0-indexed)
            case length(Fields) >= 9 of
                true ->
                    UserID = lists:nth(9, Fields),
                    io:format("User ID: ~s~n", [UserID]);
                false -> ok
            end;
        _ -> ok
    end
end, ColonData).
```

### Key Management Workflow

```erlang
%% 1. Generate keys externally with: gpg --gen-key
%% 2. Export public key: gpg --armor --export user@example.com
%% 3. Import into your application's keyring:
PublicKey = file:read_file("pubkey.asc"),
erl_gpg_api:import_key(PublicKey, "").

%% 4. Now you can encrypt for that user:
erl_gpg_api:encrypt(<<"Secret">>, ["user@example.com"], "").
```

### Finding the Correct Email/Key ID

To find which email address or key ID to use for encryption:

#### Method 1: Use the list_keys function (recommended)

```erlang
%% Start the application
application:start(erl_gpg).

%% List all public keys with pretty formatting
{ok, Result} = erl_gpg_api:list_keys().
io:format("~s", [erl_gpg_api:format_keys(Result)]).

%% This shows all available keys with:
%% - Key IDs (short form like 8EAC160D)
%% - Email addresses from UIDs
%% - Fingerprints
%% - Validity and expiration info
```

#### Method 2: Use GPG command line

```bash
# List all public keys (for encryption)
gpg --list-keys

# Example output:
# pub   rsa4096 2024-01-01 [SC]
#       1234567890ABCDEF1234567890ABCDEF12345678
# uid           [ultimate] Alice Smith <alice@example.com>
# sub   rsa4096 2024-01-01 [E]
```

You can use **any of these** for the Recipients list:
- Email address: `"alice@example.com"`
- Full name: `"Alice Smith"`
- Key ID (short): `"12345678"` (last 8 chars)
- Key ID (long): `"1234567890ABCDEF1234567890ABCDEF12345678"`

#### Method 3: Parse import result

```erlang
%% After importing a key
{ok, Result} = erl_gpg_api:import_key(PublicKeyData, "").

%% Parse the status lines to find the imported key ID
StatusLines = maps:get(status, Result),
lists:foreach(fun(#{tag := Tag, args := Args}) ->
    case Tag of
        <<"IMPORT_OK">> ->
            [_Reason, KeyID | _] = Args,
            io:format("Imported key: ~s~n", [KeyID]);
        _ -> ok
    end
end, StatusLines).
```

### Verifying a Signature

GPG signatures come in different formats. The current `verify` implementation
handles **clearsigned messages** (signature embedded with the data).

#### Clearsigned Message (Current Implementation)

```erlang
%% Data with embedded signature
SignedData = <<"-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

This is the message content
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCAAdFiEE...
-----END PGP SIGNATURE-----">>,

{ok, Result} = erl_gpg_api:verify(SignedData, "").

%% Check verification status
Status = maps:get(status, Result),
case lists:any(fun(#{tag := Tag}) -> Tag =:= <<"GOODSIG">> end, Status) of
    true -> io:format("Good signature~n");
    false -> io:format("Bad or missing signature~n")
end.
```

#### Verifying a Detached Signature (CSR Use Case)

For a **CSR signed with a detached GPG signature**, you can verify the
signature against the original data using the `verify_detached/3` function.

**Example - Verifying a Signed CSR**:
```erlang
%% The CSR content (what was signed)
CSRData = <<"-----BEGIN CERTIFICATE REQUEST-----
MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMx...
-----END CERTIFICATE REQUEST-----">>,

%% The detached GPG signature
SignatureData = <<"-----BEGIN PGP SIGNATURE-----

iQIzBAABCAAdFiEExxx...
-----END PGP SIGNATURE-----">>,

%% Verify (signer's public key must be in keyring)
{ok, Result} = erl_gpg_api:verify_detached(CSRData, SignatureData, "").

%% Check who signed it
Status = maps:get(status, Result),
lists:foreach(fun(#{tag := Tag, args := Args}) ->
    case Tag of
        <<"GOODSIG">> ->
            [KeyID, Name | _] = Args,
            io:format("Good signature from ~s (Key: ~s)~n", [Name, KeyID]);
        <<"BADSIG">> ->
            io:format("BAD signature!~n");
        <<"ERRSIG">> ->
            io:format("Error checking signature~n");
        <<"VALIDSIG">> ->
            [Fingerprint, Date, Timestamp | _] = Args,
            io:format("Valid sig: ~s at ~s~n", [Fingerprint, Date]);
        _ -> ok
    end
end, Status).
```

**Important Status Tags for Verification**:
- `GOODSIG` - Signature is good, key is in keyring
- `BADSIG` - Signature is bad/tampered
- `ERRSIG` - Error checking signature (missing public key)
- `VALIDSIG` - Additional validation info (fingerprint, timestamp)
- `TRUST_ULTIMATE` / `TRUST_FULL` - Trust level of the signing key

**Verification Workflow for CSRs**:
```erlang
%% 1. Import the public key of the signer (if not already in keyring)
PublicKey = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
{ok, _} = erl_gpg_api:import_key(PublicKey, "").

%% 2. Verify the detached signature on the CSR
{ok, Result} = erl_gpg_api:verify_detached(CSRData, SignatureData, "").

%% 3. Check the result
Status = maps:get(status, Result),
IsValid = lists:any(fun(#{tag := Tag}) -> Tag =:= <<"GOODSIG">> end, Status),

case IsValid of
    true ->
        %% Extract signer info
        [#{tag := <<"GOODSIG">>, args := [_KeyID, SignerName | _]} | _] = 
            lists:filter(fun(#{tag := T}) -> T =:= <<"GOODSIG">> end, Status),
        {ok, SignerName};
    false ->
        {error, invalid_signature}
end.
```

## Result Format

All operations return a structured map:

```erlang
#{
    stdout => Binary,           %% Main output from GPG
    status => [StatusMap],      %% Parsed status lines (from --status-fd)
    colon => [ColonMap],        %% Parsed colon-format records (from --with-colons)
    raw => #{                   %% Raw unparsed data
        status_lines => [Binary],
        colon_lines => [Binary]
    },
    exit => ok | {error, {exit_status, Code}}
}
```

Status maps:
```erlang
#{tag => <<"BEGIN_ENCRYPTION">>, args => [<<"2">>, <<"9">>]}
```

Colon maps (used by list_keys):
```erlang
#{type => <<"pub">>, fields => [<<"u">>, <<"255">>, <<"22">>, <<"8EAC160D">>, ...]}
#{type => <<"uid">>, fields => [<<"u">>, <<>>, <<>>, <<>>, <<"1758357439">>, <<>>, 
                                 <<"...">>, <<>>, <<"Bob Brown <bob.brown@example.com>">>, ...]}
#{type => <<"fpr">>, fields => [<<>>, <<>>, <<>>, <<>>, <<>>, <<>>, <<>>, <<>>, 
                                 <<"D713F54429F30D060C23E6B8185088AF8EAC160D">>, <<>>]}
```

Common colon record types:
- `pub` - Public key (fields: validity, key_length, algo, key_id, creation_date, expiry_date, ...)
- `sec` - Secret (private) key
- `uid` - User ID (field 9 contains email/name)
- `fpr` - Fingerprint (field 9 contains full fingerprint)
- `sub` - Subkey
- `sig` - Signature

## Configuration

### GPG Binary Location

Override the GPG binary location:

```erlang
application:set_env(erl_gpg, gpg_binary, "/custom/path/to/gpg").
```

The library automatically searches these locations:
- `/opt/homebrew/bin/gpg` (Homebrew on Apple Silicon)
- `/usr/local/bin/gpg` (Homebrew on Intel Mac / Linux)
- `/usr/bin/gpg` (Standard Linux)
- `/bin/gpg` (Alternative)
- System PATH via `os:find_executable/1`

### Trust Model Options

All API functions accept an options parameter to control GPG behavior:

```erlang
%% Bypass key trust checks (useful for automation)
Options = [{trust_model, always}],
{ok, Result} = erl_gpg_api:encrypt(Plain, Recipients, "", Options).

%% Use isolated GPG home directory (custom keyring)
IsolatedOpts = [{home_dir, "/path/to/custom/gnupg"}],
{ok, Result2} = erl_gpg_api:encrypt(Plain, Recipients, "", IsolatedOpts).

%% Combine multiple options
CombinedOpts = [{trust_model, always}, {home_dir, "/custom/gnupg"}],
{ok, Result3} = erl_gpg_api:encrypt(Plain, Recipients, "", CombinedOpts).

%% Also available for:
erl_gpg_api:decrypt(Cipher, "", Options).
erl_gpg_api:import_key(KeyData, "", Options).
erl_gpg_api:verify(Data, "", Options).
erl_gpg_api:verify_detached(Data, Sig, "", Options).
erl_gpg_api:list_keys("", Options).

%% List secret keys instead of public keys
SecretKeyOptions = [{key_type, secret}],
{ok, Result} = erl_gpg_api:list_keys(SecretKeyOptions).
```

#### Available Options

- `{trust_model, always}` - Bypass key trust checks (useful for automation)
- `{home_dir, Path}` - Use custom GPG home directory for isolated keyring
- `{key_type, secret}` - List secret keys instead of public keys (list_keys only)

### GPG Home Directory (Isolated Keyrings)

You can use the `{home_dir, Path}` option to work with isolated GPG keyrings:

```erlang
%% Create and use an isolated keyring
CustomGPGHome = "/path/to/custom/gnupg",

%% Import a key to the isolated keyring
KeyData = <<"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...">>,
{ok, _} = erl_gpg_api:import_key(KeyData, "", [{home_dir, CustomGPGHome}]).

%% List keys in the isolated keyring
{ok, Result} = erl_gpg_api:list_keys([{home_dir, CustomGPGHome}]).

%% Encrypt using the isolated keyring
Plain = <<"Secret data">>,
Options = [{home_dir, CustomGPGHome}, {trust_model, always}],
{ok, EncResult} = erl_gpg_api:encrypt(Plain, ["user@example.com"], "", Options).
```

**Setting up an isolated keyring:**

```bash
# Create the directory
mkdir -p /path/to/custom/gnupg
chmod 700 /path/to/custom/gnupg

# Import keys using command line
gpg --homedir /path/to/custom/gnupg --import pubkey.asc

# Or import programmatically (see example above)
```

**Benefits of isolated keyrings:**
- Separate keys for different applications or security contexts
- No interference with system-wide GPG keyring
- Easier key management and cleanup
- Better security isolation


## Running Tests

```bash
rebar3 eunit
```

The test suite includes:
- **Unit tests** (20 tests): Parser tests, API error handling, supervisor tests
- **API integration tests** (5 tests): Error handling for encrypt, decrypt, import, verify operations
- **Full integration tests** (4 tests): Complete encrypt/decrypt roundtrip with isolated keyrings
  - Automatically set up temporary GPG keyrings
  - Generate test keypairs on-the-fly
  - Test encryption, decryption, key import, key listing, and multi-recipient scenarios
  - **All 4 integration tests pass** with isolated keyrings
- **Legacy test** (1 test): `test_worker_encrypt_decrypt` - Expected timeout (no keyring configured)

**Test Results**: 31 total tests - 30 passing, 1 expected timeout

## Security Considerations

- **Keyring Management**: 
  - Public keys needed for encryption must be imported first
  - Private keys needed for decryption must be in your keyring
  - Use `--list-keys` and `--list-secret-keys` to verify key availability
  
- **Key Trust**: 
  - GPG may refuse to encrypt without proper key trust levels
  - Use `--trust-model always` or properly sign/trust keys
  - Current implementation uses `--yes` to bypass some prompts

- **Passphrase Handling**: 
  - Private keys are often passphrase-protected
  - This library doesn't currently handle passphrase input
  - Use passphrase-less keys or configure `gpg-agent` for your environment

- **Isolation**: 
  - Use isolated GPG home directories for different applications via `{home_dir, Path}` option
  - Prevents key leakage between different security contexts
  - Example: `erl_gpg_api:encrypt(Data, Recipients, "", [{home_dir, "/app/gnupg"}])`

- **Data Validation**: 
  - Validate all input data before passing to GPG
  - Handle private keys securely and never log them
  - Be aware of GPG's resource usage and set appropriate timeouts
  - Operations timeout after 5 seconds

- **File Permissions**: 
  - Use appropriate permissions (0700) for GPG home directories
  - Protect private key files with 0600 permissions
  
- **Error Handling**:
  - Always check the `exit` field in results
  - Parse `status` maps for detailed operation results
  - Failed operations may still return partial data

## License

MPL-2.0

