# go-electrum [![GoDoc](https://godoc.org/github.com/konez2k/go-electrum?status.svg)](https://godoc.org/github.com/konez2k/go-electrum)

A pure Go [Electrum](https://electrum.org/) JSON-RPC client library.

## About

Note that Electrum daemon uses a random port number by default.
In order to use a stable port number, you need to change configuration variable (and restart the daemon):

```
electrum setconfig rpcport 8001
```

Electrum will also initialize rpc username / password with a random string.
To retreive the current values:

```
electrum getconfig rpcuser
electrum getconfig rpcpassword
```

## ToDo

Implemented Electrum commands based on v3.2.3.

| Command           | Implemented | Notes              |
|-------------------|-------------|--------------------|
| addrequest        | [ ]         |                    |
| addtransaction    | [ ]         |                    |
| broadcast         | [X]         |                    |
| clearrequests     | [ ]         |                    |
| create            | [ ]         | Not yet available. |
| createmultisig    | [ ]         |                    |
| createnewaddress  | [X]         |                    |
| decrypt           | [ ]         |                    |
| deserialize       | [X]         |                    |
| encrypt           | [ ]         |                    |
| freeze            | [ ]         |                    |
| getaddressbalance | [X]         |                    |
| getaddresshistory | [X]         |                    |
| getaddressunspent | [X]         |                    |
| getalias          | [ ]         |                    |
| getbalance        | [X]         |                    |
| getconfig         | [X]         |                    |
| getfeerate        | [X]         |                    |
| getmasterprivate  | [X]         |                    |
| getmerkle         | [X]         |                    |
| getmpk            | [X]         |                    |
| getprivatekeys    | [X]         |                    |
| getpubkeys        | [X]         |                    |
| getrequest        | [ ]         |                    |
| getseed           | [X]         |                    |
| getservers        | [X]         |                    |
| gettransaction    | [X]         |                    |
| getunusedaddress  | [X]         |                    |
| history           | [X]         |                    |
| importprivkey     | [ ]         |                    |
| is_synchronized   | [X]         |                    |
| ismine            | [X]         |                    |
| listaddresses     | [X]         |                    |
| listcontacts      | [ ]         |                    |
| listrequests      | [ ]         |                    |
| listunspent       | [X]         |                    |
| make_seed         | [X]         |                    |
| notify            | [X]         |                    |
| password          | [X]         |                    |
| payto             | [X]         |                    |
| paytomany         | [ ]         |                    |
| restore           | [ ]         | Not yet available. |
| rmrequest         | [ ]         |                    |
| searchcontacts    | [ ]         |                    |
| serialize         | [ ]         |                    |
| setconfig         | [X]         |                    |
| setlabel          | [ ]         |                    |
| signmessage       | [X]         |                    |
| signrequest       | [ ]         |                    |
| signtransaction   | [ ]         |                    |
| sweep             | [ ]         |                    |
| unfreeze          | [ ]         |                    |
| validateaddress   | [X]         |                    |
| verifymessage     | [X]         |                    |
| version           | [X]         |                    |

## Package Tests

To run the go tests use the environment variables: RPCHOST, RPCPORT, RPCUSER, RPCPASSWORD, WALLETPATH, WALLETPASSWORD

```
RPCHOST=127.0.0.1 RPCPORT=7001 RPCUSER=user RPCPASSWORD=usertest go test
```

TODO: test coverage needs to be implemented.

## Usage

See [example/](https://github.com/konez2k/go-electrum/tree/master/example) for more.

## License

The MIT License (MIT)

Copyright (c) 2018 konez2k

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.