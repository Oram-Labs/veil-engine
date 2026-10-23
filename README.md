# veil-engine

The open-source core of [Veil](https://getveil.tech): it finds personal data and secrets in text, replaces them with placeholders such as `[EMAIL_1]` before the text goes to an AI model, and puts the real values back into the reply.

```text
you write          Email ana@example.com about card 4111 1111 1111 1111
the model sees     Email [EMAIL_1] about card [CARD_1]
the model replies  I emailed [EMAIL_1].
you see            I emailed ana@example.com.
```

| Crate | What it does |
|---|---|
| [`veil-engine`](crates/engine) | Detection, placeholders and restoration. No file or network access, no logging. |
| [`veil-vault`](crates/vault) | Encrypted storage for the placeholders, with the key in the OS keychain. |

Start with the [engine's README](crates/engine/README.md). [THREAT_MODEL.md](THREAT_MODEL.md) says what the crates protect against and what they don't.

## Building and testing

```sh
cargo test
cargo test -p veil-engine --no-default-features   # without the phone detector
```

`fixtures/corpus` holds the detection test cases. Every value in it is made up, including the API keys and tokens, which only have the shape of real ones.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
