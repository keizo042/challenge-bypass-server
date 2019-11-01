package main

import "github.com/privacypass/challenge-bypass-server/crypto"

// loadKeys loads a signing key and optionally loads a file containing old keys for redemption validation
func (c *Server) loadKeys() error {
	if c.SignKeyFilePath == "" {
		return ErrEmptyKeyPath
	}
	if c.CommFilePath == "" {
		return ErrEmptyCommPath
	}

	// Parse current signing key
	_, currkey, err := crypto.ParseKeyFile(c.SignKeyFilePath, true)
	if err != nil {
		return err
	}
	c.signKey = currkey[0]
	c.redeemKeys = append(c.redeemKeys, c.signKey)

	// optionally parse old keys that are valid for redemption
	if c.RedeemKeysFilePath != "" {
		errLog.Println("Adding extra keys for verifying token redemptions")
		_, oldKeys, err := crypto.ParseKeyFile(c.RedeemKeysFilePath, false)
		if err != nil {
			return err
		}
		c.redeemKeys = append(c.redeemKeys, oldKeys...)
	}

	return nil
}
