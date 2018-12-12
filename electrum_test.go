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

package electrum

import (
	"os"
	"strconv"
	"testing"
)

type (
	testEnv struct {
		Host           string
		Port           int
		User           string
		Password       string
		WalletPath     string
		WalletPassword string
		Debug          bool
	}
)

var env testEnv

func checkEnvironmentVariables(t *testing.T) {
	var port int
	var debug bool

	if v, err := strconv.Atoi(os.Getenv("RPCPORT")); err == nil {
		port = v
	}

	if d, err := strconv.ParseBool(os.Getenv("DEBUG")); err == nil {
		debug = d
	}

	env = testEnv{
		Host:           os.Getenv("RPCHOST"),
		Port:           port,
		User:           os.Getenv("RPCUSER"),
		Password:       os.Getenv("RPCPASSWORD"),
		WalletPath:     os.Getenv("WALLETPATH"),
		WalletPassword: os.Getenv("WALLETPASSWORD"),
		Debug:          debug,
	}

	// check required env variables.
	if env.Host == "" {
		t.Fatal("missing RPCHOST")
	}

	if env.Port == 0 {
		t.Fatal("missing RPCPORT")
	}

	if env.User == "" {
		t.Fatal("missing RPCUSER")
	}

	if env.Password == "" {
		t.Fatal("missing RPCPASSWORD")
	}
}

func TestDaemonStatus(t *testing.T) {
	checkEnvironmentVariables(t)

	c, err := New(env.Host, env.Port, env.User, env.Password, false)
	if err != nil {
		t.Fatalf("could not connect to electrum daemon: %v", err)
	}

	if env.Debug {
		c.Debug = true
	}

	_, err = c.GetDaemonStatus()
	if err != nil {
		t.Fatalf("could not retreive daemon status: %v", err)
	}
}
