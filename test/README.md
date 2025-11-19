# erl_gpg Tests

## Running the Sign Function Tests

The `erl_gpg_sign_tests.erl` module tests the GPG signing functionality.

### Setup

To run the tests, you need a GPG key available for testing. Set the environment variable:

```bash
export ERL_GPG_TEST_KEY="your-gpg-key-id"
```

You can find your key ID with:
```bash
gpg --list-secret-keys
```

### Running Tests

```bash
# Run all erl_gpg tests
rebar3 eunit

# Run just the sign tests
rebar3 eunit --module=erl_gpg_sign_tests
```

### Without a Test Key

If you don't set `ERL_GPG_TEST_KEY`, the tests will be skipped with a message:
```
"No test GPG key configured (set ERL_GPG_TEST_KEY)"
```

### What's Tested

- `sign/2,3` - Clearsign operations (embedded signature)
- `sign_detached/3,4` - Detached signature operations
- Error handling (invalid key IDs, empty data)
- Output format verification (PEM structure, base64 encoding)
- Comparison between clearsign and detached signatures
