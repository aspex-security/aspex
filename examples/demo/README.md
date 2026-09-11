# Aspex demo environment

A deterministic, fake agent environment that shows the whole loop in two
minutes. No real credentials, no real servers are launched (everything runs
with `--no-exec`), nothing leaves your machine.

What is in it:

| Piece | Why |
|---|---|
| `filesystem` scoped to the (fake) home directory | the sensitive read half of an exfiltration path, and the write half of a persistence path |
| `browser` (Playwright) | arbitrary HTTPS egress and external content ingress |
| `github` with a keychain-resolved token | a benign powerful capability: a fixed channel, no plaintext secret |
| `sequential-thinking` | a benign server with no dangerous capability |
| a `PostToolUse` hook running `prettier` | a benign hook, surfaced as INFO |
| one recorded session | a README is fetched, `~/.aws/credentials` is read 7 seconds later, then an issue is created |

Run it:

```sh
./examples/demo/run.sh
```

The script copies `home/` to a temporary directory, rewrites the
`__DEMO_HOME__` placeholders to that path, and sets `HOME` there, so Aspex
discovers only the demo configuration and logs and the filesystem server is
scoped to the (fake) home directory, exactly as on a real machine. The script
prints the temporary path; to continue by hand:

```sh
export HOME=/tmp/aspex-demo.XXXX          # the path the script printed
aspex scan --no-exec                                   # what CAN happen: AP001 + AP003
aspex explain "Can this agent leak AWS credentials?"   # YES, with what breaks it
aspex simulate --restrict-filesystem "filesystem=$HOME/projects/acme"   # WHAT IF: paths drop
aspex trace --since 3650d                              # what DID happen in the recorded session
aspex trace provenance --since 3650d                   # README fetch -> credential read, timed
aspex explore --since 3650d                            # investigate visually (loopback only)
```

Expected journey: scan shows a critical exfiltration path and a critical
persistence path; explain says YES and names the two controls; simulate shows
that narrowing the filesystem root removes them; trace shows the credential
read that followed the README fetch and says which part is observed and which
is inferred.
