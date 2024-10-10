## Building and running. 

run the following command in the repo root:

```
RUST_LOG="trace" cargo run enode://e66beb15301e8ede4d42354fc94a6531b817248d933f34af1d27483ca52c3628540bb01369466f6df59e8d08a2308796a6f45a6493c861baf69d4527b53bc9b6@127.0.0.1:30303
cargo run enode://b07b139cc095dbe9bf4b8ebc95ddb9a04a76d5bb3447cfff28c1ea2e717ec579694e5181285bc927b344ee5d66307228cdeebc40c618341e19f405466dc60bb7@18.193.86.62:30303
```

It should take a full enode format, it is thought in order to be capable to connect to multiple enodes and you can pass multiple enodes as arguments, but there are a bunch of pieces missing yet that make that not yet possible. 

Enodes can be grabbed from https://ethernodes.org/

I ran and tested using a local geth instance with logging,  I noticed that public enodes sometimes refuse opening the TCP connection. 

Apparently the MAC's we get from other nodes are detected as mismatching, getting them from geth nodes is a-ok. Something is off.