package main

import (
	"flag"

	"github.com/privacypass/challenge-bypass-server/crypto"
)

func main() {
	var configFile string
	var err error
	srv := *DefaultServer

	flag.StringVar(&configFile, "config", "", "local config file for development (overrides cli options)")
	flag.StringVar(&srv.BindAddress, "addr", "127.0.0.1", "address to listen on")
	flag.StringVar(&srv.SignKeyFilePath, "key", "", "path to the current secret key file for signing tokens")
	flag.StringVar(&srv.RedeemKeysFilePath, "redeem_keys", "", "(optional) path to the file containing all other keys that are still used for validating redemptions")
	flag.StringVar(&srv.CommFilePath, "comm", "", "path to the commitment file")
	flag.IntVar(&srv.ListenPort, "p", 2416, "port to listen on")
	flag.IntVar(&srv.MetricsPort, "m", 2417, "metrics port")
	flag.IntVar(&srv.MaxTokens, "maxtokens", 100, "maximum number of tokens issued per request")
	flag.StringVar(&srv.keyVersion, "keyversion", "1.0", "version sent to the client for choosing consistent key commitments for proof verification")
	flag.Parse()

	if configFile != "" {
		srv, err = loadConfigFile(configFile)
		if err != nil {
			errLog.Fatal(err)
			return
		}
	}

	if configFile == "" && (srv.SignKeyFilePath == "" || srv.CommFilePath == "") {
		flag.Usage()
		return
	}

	if err := srv.loadKeys(); err != nil {
		errLog.Fatal(err)
		return
	}

	// Get bytes for public commitment to private key
	GBytes, HBytes, err := crypto.ParseCommitmentFile(srv.CommFilePath)
	if err != nil {
		errLog.Fatal(err)
		return
	}

	// Retrieve the actual elliptic curve points for the commitment
	// The commitment should match the current key that is being used for
	// signing
	//
	// We only support curve point commitments for P256-SHA256
	srv.G, srv.H, err = crypto.RetrieveCommPoints(GBytes, HBytes, srv.signKey)
	if err != nil {
		errLog.Fatal(err)
		return
	}

	if err := srv.ListenAndServe(); err != nil {
		errLog.Fatal(err)
		return
	}
}
