package metrics

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// caPoolFileStore is a store for client CA Pools, such as trust store bundles.
type caPoolFileStore struct {
	// The location of the trust store bundle. Needs to be a series of PEM
	// encoded certificates.
	location string
}

func (c caPoolFileStore) current() (*x509.CertPool, error) {
	data, err := os.ReadFile(c.location)
	if err != nil {
		return nil, fmt.Errorf("failed to load clientCA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("invalid client CA file: %v", c.location)
	}

	return pool, nil
}

// configures and returns options for a secure metrics
// server using mTLS (Transport Layer Security) for encryption based on the
// provided metrics certificate path.
func TLSConfig(certdir string) (*tls.Config, error) {

	clientCALocation := certdir + "/ca.crt"
	clientCAStore := caPoolFileStore{location: clientCALocation}
	clientCA, err := clientCAStore.current()

	if err != nil {
		return nil, fmt.Errorf("TLS config Pool file: %w", err)
	}

	config := new(tls.Config)
	config.ClientAuth = tls.RequireAndVerifyClientCert
	config.ClientCAs = clientCA
	config.GetCertificate = func(_ *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
		cert2, err2 := tls.LoadX509KeyPair(certdir+"/tls.crt", certdir+"/tls.key")
		if err2 != nil {
			return nil, fmt.Errorf("failed to load X509 key pair: %w", err)
		}
		return &cert2, nil
	}
	// Setting config.ClientCAs is only done during initialization.
	// Thus, setting the config.GetConfigForClient callback is needed to dynamically
	// pick up the rotated client CA cert. ???
	config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		newCfg := config.Clone()
		clientCA, err := clientCAStore.current()
		if err != nil {
			return nil, fmt.Errorf("TLS config clientCA: %w", err)
		}
		newCfg.ClientCAs = clientCA
		return newCfg, nil
	}

	return config, nil
}

// trial to take TLSConfig creation from Hubble
func TLSConfigHubble(certdir string) (*tls.Config, error) {
	var metricsTLSConfig *certloader.WatchedServerConfig
	metricsTLSConfigChan, err := certloader.FutureWatchedServerConfig(
		h.log.With(logfields.Config, "hubble-metrics-server-tls"),
		h.config.MetricsServerTLSClientCAFiles,
		h.config.MetricsServerTLSCertFile,
		h.config.MetricsServerTLSKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Hubble metrics server TLS configuration: %w", err)
	}
	waitingMsgTimeout := time.After(30 * time.Second)
	for metricsTLSConfig == nil {
		select {
		case metricsTLSConfig = <-metricsTLSConfigChan:
		case <-waitingMsgTimeout:
			h.log.Info("Waiting for Hubble metrics server TLS certificate and key files to be created")
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout while waiting for Hubble metrics server TLS certificate and key files to be created: %w", ctx.Err())
		}
	}
	go func() {
		<-ctx.Done()
		metricsTLSConfig.Stop()
	}()
}
