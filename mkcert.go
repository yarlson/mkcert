// Copyright 2023 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package main provides the mkcert functionality as a library.
package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// MkCert provides an API for creating locally-trusted development certificates.
type MkCert struct {
	// underlying implementation
	m *mkcert
}

// CertOptions represents options for certificate creation.
type CertOptions struct {
	ECDSA    bool   // Use ECDSA instead of RSA
	Client   bool   // Generate a certificate for client authentication
	PKCS12   bool   // Generate a PKCS#12 file
	CertFile string // Custom certificate file path
	KeyFile  string // Custom key file path
	P12File  string // Custom PKCS#12 file path
}

// New creates a new MkCert instance.
func New() (*MkCert, error) {
	caRoot := getCAROOT()
	if caRoot == "" {
		return nil, fmt.Errorf("failed to find the default CA location, set one as the CAROOT env var")
	}

	if err := os.MkdirAll(caRoot, 0755); err != nil {
		return nil, fmt.Errorf("failed to create the CAROOT: %w", err)
	}

	m := &mkcert{CAROOT: caRoot}
	m.loadCA()

	return &MkCert{m: m}, nil
}

// NewWithCARoot creates a new MkCert instance with a custom CA root directory.
func NewWithCARoot(caRoot string) (*MkCert, error) {
	if err := os.MkdirAll(caRoot, 0755); err != nil {
		return nil, fmt.Errorf("failed to create the CAROOT: %w", err)
	}

	m := &mkcert{CAROOT: caRoot}
	m.loadCA()

	return &MkCert{m: m}, nil
}

// Install installs the local CA in the system trust store.
func (m *MkCert) Install() error {
	if storeEnabled("system") && !m.m.checkPlatform() {
		if m.m.installPlatform() {
			fmt.Println("The local CA is now installed in the system trust store!")
		}
		m.m.ignoreCheckFailure = true
	}

	if storeEnabled("nss") && hasNSS {
		if !m.m.checkNSS() {
			if hasCertutil && m.m.installNSS() {
				fmt.Printf("The local CA is now installed in the %s trust store (requires browser restart)!\n", NSSBrowsers)
			}
		}
	}

	if storeEnabled("java") && hasJava {
		if !m.m.checkJava() {
			if hasKeytool {
				m.m.installJava()
				fmt.Println("The local CA is now installed in Java's trust store!")
			}
		}
	}

	return nil
}

// Uninstall uninstalls the local CA from the system trust store.
func (m *MkCert) Uninstall() error {
	if storeEnabled("nss") && hasNSS && hasCertutil {
		m.m.uninstallNSS()
	}

	if storeEnabled("java") && hasJava && hasKeytool {
		m.m.uninstallJava()
	}

	if storeEnabled("system") {
		m.m.uninstallPlatform()
	}

	return nil
}

// MakeCert creates a new certificate for the given hostnames.
func (m *MkCert) MakeCert(hostnames []string, options *CertOptions) error {
	if m.m.caKey == nil {
		return fmt.Errorf("can't create new certificates because the CA key (rootCA-key.pem) is missing")
	}

	if options != nil {
		m.m.ecdsa = options.ECDSA
		m.m.client = options.Client
		m.m.pkcs12 = options.PKCS12
		m.m.certFile = options.CertFile
		m.m.keyFile = options.KeyFile
		m.m.p12File = options.P12File
	}

	m.m.makeCert(hostnames)
	return nil
}

// MakeCertFromCSR creates a new certificate from a CSR file.
func (m *MkCert) MakeCertFromCSR(csrPath string, certFile string) error {
	if m.m.caKey == nil {
		return fmt.Errorf("can't create new certificates because the CA key (rootCA-key.pem) is missing")
	}

	m.m.csrPath = csrPath
	if certFile != "" {
		m.m.certFile = certFile
	}

	m.m.makeCertFromCSR()
	return nil
}

// CACert returns the current CA certificate.
func (m *MkCert) CACert() *x509.Certificate {
	return m.m.caCert
}

// CARoot returns the directory where the CA files are stored.
func (m *MkCert) CARoot() string {
	return m.m.CAROOT
}

// CreateCA creates a new CA if it doesn't exist.
// Normally this is done automatically, but this method allows explicitly creating a new CA.
func (m *MkCert) CreateCA() error {
	m.m.newCA()
	return nil
}

// CAFiles returns the paths to the CA certificate and key files.
func (m *MkCert) CAFiles() (certPath, keyPath string) {
	return filepath.Join(m.m.CAROOT, rootName), filepath.Join(m.m.CAROOT, rootKeyName)
}
