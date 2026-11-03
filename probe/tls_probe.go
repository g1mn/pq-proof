// Command tls_probe is PQ-Proof's fixed-version TLS client (and reference server).
//
// It is built once, statically (CGO_ENABLED=0, standard library only), and the same binary is
// copied into every microVM, so a red baseline says something about the server and not about an
// old client that does not know the group's name.
//
//	tls_probe version
//	tls_probe cert -hosts=localhost,127.0.0.1 DIR      writes DIR/ca.pem, DIR/cert.pem, DIR/key.pem (mode 0644)
//	tls_probe serve -addr=127.0.0.1:4433 -groups=X25519MLKEM768,X25519 -cert=PATH -key=PATH
//	tls_probe connect -groups=X25519MLKEM768 -ca=PATH -servername=NAME [-wait=10s] HOST:PORT
//
// connect prints "key: value" lines (probe, target, offered, result, protocol, group, error) and
// exits 0 when the handshake completes, 1 when it fails and 2 on a usage error.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const version = "0.2.0"

var groupNames = map[string]tls.CurveID{
	"X25519MLKEM768":     tls.X25519MLKEM768,
	"SecP256r1MLKEM768":  tls.SecP256r1MLKEM768,
	"SecP384r1MLKEM1024": tls.SecP384r1MLKEM1024,
	"X25519":             tls.X25519,
	"P-256":              tls.CurveP256,
	"P-384":              tls.CurveP384,
	"P-521":              tls.CurveP521,
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Printf("tls_probe %s (%s)\n", version, runtime.Version())
		return
	case "cert":
		err = cert(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:])
	case "connect":
		os.Exit(connect(os.Args[2:]))
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tls_probe:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tls_probe version | cert | serve | connect (see the source)")
	os.Exit(2)
}

func parseGroups(s string) ([]tls.CurveID, error) {
	var ids []tls.CurveID
	for _, name := range strings.Split(s, ",") {
		id, ok := groupNames[name]
		if !ok {
			return nil, fmt.Errorf("unknown group %q", name)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func cert(args []string) error {
	fs := flag.NewFlagSet("cert", flag.ExitOnError)
	hosts := fs.String("hosts", "localhost,127.0.0.1", "comma-separated DNS names and IPs for the leaf")
	fs.Parse(args)
	if fs.NArg() != 1 {
		usage()
	}
	dir := fs.Arg(0)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tls_probe test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tls_probe test server"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, h := range strings.Split(*hosts, ",") {
		if ip := net.ParseIP(h); ip != nil {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
		} else {
			leaf.DNSNames = append(leaf.DNSNames, h)
		}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	// World-readable on purpose: this is throwaway test material for one microVM, and the servers
	// under test run as unprivileged users that must read it. Only root can change it.
	for name, block := range map[string]*pem.Block{
		"ca.pem":   {Type: "CERTIFICATE", Bytes: caDER},
		"cert.pem": {Type: "CERTIFICATE", Bytes: leafDER},
		"key.pem":  {Type: "PRIVATE KEY", Bytes: keyDER},
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o644); err != nil { // WriteFile's mode is cut by the umask
			return err
		}
	}
	return nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:4433", "listen address")
	groups := fs.String("groups", "X25519MLKEM768,X25519", "groups to accept, in order")
	certFile := fs.String("cert", "", "certificate (PEM)")
	keyFile := fs.String("key", "", "private key (PEM)")
	fs.Parse(args)
	ids, err := parseGroups(*groups)
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", *addr, &tls.Config{Certificates: []tls.Certificate{pair}, CurvePreferences: ids,
		MinVersion: tls.VersionTLS13})
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			c.(*tls.Conn).Handshake()
		}(c)
	}
}

func connect(args []string) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	groups := fs.String("groups", "X25519MLKEM768", "groups to offer, in order")
	caFile := fs.String("ca", "", "CA certificate (PEM) the server certificate must chain to")
	serverName := fs.String("servername", "localhost", "server name to send and verify")
	wait := fs.Duration("wait", 10*time.Second, "keep retrying a refused connection this long")
	if fs.Parse(args) != nil || fs.NArg() != 1 || *caFile == "" {
		fmt.Fprintln(os.Stderr, "usage: tls_probe connect -groups=G1,G2 -ca=PATH [-servername=NAME] [-wait=10s] HOST:PORT")
		return 2
	}
	target := fs.Arg(0)
	fmt.Printf("probe: tls_probe %s (%s)\ntarget: %s\noffered: %s\n", version, runtime.Version(), target, *groups)
	fail := func(err error) int {
		fmt.Printf("result: failed\nerror: %s\n", strings.ReplaceAll(err.Error(), "\n", " "))
		return 1
	}
	ids, err := parseGroups(*groups)
	if err != nil {
		return fail(err)
	}
	caPEM, err := os.ReadFile(*caFile)
	if err != nil {
		return fail(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return fail(errors.New("no certificate in " + *caFile))
	}
	conf := &tls.Config{RootCAs: roots, ServerName: *serverName, CurvePreferences: ids}
	deadline := time.Now().Add(*wait)
	var raw net.Conn
	for {
		raw, err = net.DialTimeout("tcp", target, 5*time.Second)
		if err == nil || !errors.Is(err, syscall.ECONNREFUSED) || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		return fail(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn := tls.Client(raw, conf)
	if err := conn.Handshake(); err != nil {
		return fail(err)
	}
	st := conn.ConnectionState()
	fmt.Printf("result: connected\nprotocol: %s\ngroup: %s\n", tls.VersionName(st.Version), groupName(st.CurveID))
	return 0
}

func groupName(id tls.CurveID) string {
	for name, v := range groupNames {
		if v == id {
			return name
		}
	}
	return id.String()
}
