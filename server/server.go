package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	btd "github.com/privacypass/challenge-bypass-server"
	"github.com/privacypass/challenge-bypass-server/crypto"
)

var DefaultServer = &Server{
	BindAddress: "127.0.0.1",
	ListenPort:  2416,
	MetricsPort: 2417,
	MaxTokens:   100,
}
var (
	Version         = "dev"
	maxBackoffDelay = 1 * time.Second
	maxRequestSize  = int64(20 * 1024) // ~10kB is expected size for 100*base64([64]byte) + ~framing

	ErrEmptyKeyPath        = errors.New("key file path is empty")
	ErrNoSecretKey         = errors.New("server config does not contain a key")
	ErrRequestTooLarge     = errors.New("request too large to process")
	ErrUnrecognizedRequest = errors.New("received unrecognized request type")
	// Commitments are embedded straight into the extension for now
	ErrEmptyCommPath = errors.New("no commitment file path specified")

	errLog *log.Logger = log.New(os.Stderr, "[btd] ", log.LstdFlags|log.Lshortfile)
)

type Server struct {
	BindAddress        string `json:"bind_address,omitempty"`
	ListenPort         int    `json:"listen_port,omitempty"`
	MetricsPort        int    `json:"metrics_port,omitempty"`
	MaxTokens          int    `json:"max_tokens,omitempty"`
	SignKeyFilePath    string `json:"key_file_path"`
	RedeemKeysFilePath string `json:"redeem_keys_file_path"`
	CommFilePath       string `json:"comm_file_path"`

	signKey    []byte        // a big-endian marshaled big.Int representing an elliptic curve scalar for the current signing key
	redeemKeys [][]byte      // current signing key + all old keys
	G          *crypto.Point // elliptic curve point representation of generator G
	H          *crypto.Point // elliptic curve point representation of commitment H to signing key
	keyVersion string        // the version of the key that is used
}

func (c *Server) ListenAndServe() error {
	if len(c.signKey) == 0 {
		return ErrNoSecretKey
	}

	addr := fmt.Sprintf("%s:%d", c.BindAddress, c.ListenPort)
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	errLog.Printf("blindsigmgmt starting, version: %v", Version)
	errLog.Printf("listening on %s", addr)

	// Initialize prometheus endpoint

	// Log errors without killing the entire server
	errorChannel := make(chan error)
	go func() {
		for err := range errorChannel {
			if err == nil {
				continue
			}
			errLog.Printf("%v", err)
		}
	}()
	return c.serve(listener, errorChannel)
}

// return nil to exit without complaint, caller closes
func (c *Server) handle(conn *net.TCPConn) error {
	// Read the request but never more than a worst-case assumption
	buf := &bytes.Buffer{}
	limitedConn := io.LimitReader(conn, maxRequestSize)
	if _, err := io.Copy(buf, limitedConn); err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() && buf.Len() > 0 {
		}
	}

	var wrapped btd.BlindTokenRequestWrapper
	if err := json.Unmarshal(buf.Bytes(), &wrapped); err != nil {
		return err
	}

	var request btd.BlindTokenRequest
	if err := json.Unmarshal(wrapped.Request, &request); err != nil {
		return err
	}

	switch request.Type {
	case btd.ISSUE:
		err := btd.HandleIssue(conn, request, c.signKey, c.keyVersion, c.G, c.H, c.MaxTokens)
		if err != nil {
			return err
		}
	case btd.REDEEM:
		err := btd.HandleRedeem(conn, request, wrapped.Host, wrapped.Path, c.redeemKeys)
		if err != nil {
			// anything other than "success" counts as a VERIFY_ERROR
			conn.Write([]byte(err.Error()))
			return err
		}
	default:
		errLog.Printf("unrecognized request type \"%s\"", request.Type)
		return ErrUnrecognizedRequest
	}
	return nil
}

// loadKeys loads a signing key and optionally loads a file containing old keys for redemption validation
func (c *Server) loadKeys() error {
	if c.SignKeyFilePath == "" {
		return ErrEmptyKeyPath
	} else if c.CommFilePath == "" {
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

func (c *Server) serve(listener *net.TCPListener, errorChannel chan error) error {
	for {
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			errorChannel <- err
			continue
		}
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(1 * time.Minute)
		// This is directly in the user's path, an overly slow connection should just fail
		tcpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		go func() {
			errorChannel <- c.handle(tcpConn)
			tcpConn.Close()
		}()
	}
}
