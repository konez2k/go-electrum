// Copyright 2018 konez2k. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/*

A pure Go Electrum (https://electrum.org/) JSON-RPC client library.

Note that Electrum daemon uses a random port by default.
In order to use a stable port number, you need to change configuration variable rpcport and restart the daemon:

	electrum setconfig rpcport 8001

Electrum will also initialize rpc with "user" as rpcuser and rpcpassword with a random string.
To retreive the current values:

	electrum getconfig rpcuser
	electrum getconfig rpcpassword

Check the exmaples folder (https://github.com/konez2k/go-electrum/tree/master/examples) for additional usage examples.

To run the go tests use the environment variables: RPCHOST, RPCPORT, RPCUSER, RPCPASSWORD, WALLETPATH, WALLETPASSWORD

*/
package electrum // import "github.com/konez2k/go-electrum"
