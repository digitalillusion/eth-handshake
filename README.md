# eth-handshake

Tool that implements the handshake of RLPx, a TCP-based transport protocol used for communication among Ethereum nodes.

Code challenge implemented as
[recruitment exercise](https://github.com/eqlabs/recruitment-exercises/blob/master/node-handshake.md).

## Getting Started

These instructions will give you a copy of the project up and running on
your local machine for development and testing purposes. 

### Prerequisites

Requirements for the software and other tools to build and test
- [Rust](https://www.rust-lang.org/tools/install)
- [cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)
- [git](https://git-scm.com/downloads)
- [docker](https://docs.docker.com/engine/install/)

### Installing

In order to execute the program you need to clone it on your local hard drive, build it and run it

Clone the git repository and move to the created directory:

```sh
git clone git@github.com:digitalillusion/eth-handshake.git
cd eth-handshake
```

Run a release cargo build:

```sh
cargo build --release
```

## Running

1. Run a couple of ethereum nodes
```sh
docker pull ethereum/client-go
docker run -it -p 30303:30303 ethereum/client-go 
docker run -it -p 30304:30304 ethereum/client-go --port 30304
``````
2. Note down their ids, they will appear in the docker logs like:

```
    INFO [08-29|10:37:25.217] Started P2P networking                   self=enode://02248bf69e82b15c6160178cc611af179e2b646be15512448d165119cc53eb7ef1d6deab5ab4040dd8a7da2a0304865a6a240fd297937ee9c67eb8de3856c5b2@127.0.0.1:30303

    INFO [08-29|10:37:26.484] Started P2P networking                   self=enode://2d2aec6ad36ec0f73d2341007cfeb5072af02f61f419d6f7bd371b923f93ccd358d4c340bc516add5e19237646c63e125fcca09ec5ae5b9a48835518583825f3@127.0.0.1:30304
```
3. Run the release version passing the two nodes as arguments:

```sh
RUST_LOG=info target/release/eth-handshake "enode://02248bf69e82b15c6160178cc611af179e2b646be15512448d165119cc53eb7ef1d6deab5ab4040dd8a7da2a0304865a6a240fd297937ee9c67eb8de3856c5b2@127.0.0.1:30303" "enode://2d2aec6ad36ec0f73d2341007cfeb5072af02f61f419d6f7bd371b923f93ccd358d4c340bc516add5e19237646c63e125fcca09ec5ae5b9a48835518583825f3@127.0.0.1:30304"
```

4. You will see interleaving logs of the client handshaking and sending ping-pong messages toward the ethereum nodes. This happens because:
  * The client is non-blocking and asynchronous, so peer connection is operated in parallel
  * The ping-pong message would not happen if the handshake was not successful, so it's the verifiable proof of it being successful

## Producing documentation

The code contains rustdoc comments. In order to produce the HTML documentation and view it in browser it's sufficient to run:

```sh
cargo doc --open
```
## Running the tests

There are a few unit tests available that can be run:

```sh
cargo test
```

## Code coverage

`grcov` produces the correct output in either HTML or GitLab compatible format.

**Instrumentation**
```sh
rustup component add llvm-tools-preview
cargo install grcov

export LLVM_PROFILE_FILE="eth-handshake-%p-%m.profraw"
export RUSTFLAGS="-Cinstrument-coverage"

makers clean
makers build
makers test
```

**HTML report generation**

This will generate a static website in a folder (`target/coverage`), including badges:

```sh
grcov . -s . -t html --binary-path ./target/debug --llvm --branch --ignore-not-existing --ignore "/*" -o ./target/coverage
```

Once generated, you can remove the `*.profraw` files

```sh
find . \( -name "*.profraw" \) -delete
```

## Versioning

We use [Semantic Versioning](http://semver.org/) for versioning. For the versions
available, see the [tags on this
repository](https://github.com/digitalillusion/eth-handshake/tags).

## License (See LICENSE file for full license)

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

## Acknowledgments

  - https://github.com/paradigmxyz/reth
  - https://github.com/ethereum/devp2p/blob/master/rlpx.md
