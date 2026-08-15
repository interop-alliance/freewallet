# Decision records

Durable records of cross-repo decisions this repo owns: the decision, its
rationale, the alternatives rejected, and the conditions for revisiting it.
The convention and the record template are canonical in
[isomorphic-lib-template's `decisions/`](https://github.com/interop-alliance/isomorphic-lib-template/tree/main/decisions);
copy its `TEMPLATE.md` for a new record (`NNNN-kebab-case-slug.md`,
zero-padded, sequential, never renumbered).

A decision earns a record here only when this repo owns the contract it
binds. Most contracts freewallet participates in are owned elsewhere (the
spec repos, `@interop/wallet-core`, `@interop/was-client`), so their records
live in those repos.
