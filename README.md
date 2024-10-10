## Building and running. 

run the following command in the repo root:

```
RUST_LOG="trace" cargo run enode://e66beb15301e8ede4d42354fc94a6531b817248d933f34af1d27483ca52c3628540bb01369466f6df59e8d08a2308796a6f45a6493c861baf69d4527b53bc9b6@127.0.0.1:30303
```

It should take a full enode format, it is thought in order to be capable to connect to multiple enodes and you can pass multiple enodes as arguments, but there are a bunch of pieces missing yet that make that not yet possible. 

Enodes can be grabbed from https://ethernodes.org/

I ran and tested using a local geth instance with logging, public enodes I noticed that sometimes refuse opening the TCP connection. 