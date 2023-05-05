package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/obaydullahmhs/k8s-extended-apiserver/lib/certstore"
	"github.com/obaydullahmhs/k8s-extended-apiserver/lib/server"
	"github.com/spf13/afero"
	"k8s.io/client-go/util/cert"
	"log"
	"net"
	"net/http"
)

var crtPath = "/home/appscodepc/go/src/github.com/obaydullahmhs/k8s-extended-apiserver/certs"

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "OK")
}

func main() {
	var proxy = false
	flag.BoolVar(&proxy, "receive-proxy-request", proxy, "receive forwarded requests from apiserver")
	flag.Parse()

	fs := afero.NewOsFs()
	store, err := certstore.NewCertStore(fs, crtPath)
	if err != nil {
		log.Fatalln(err)
	}
	err = store.NewCA("animal")
	if err != nil {
		log.Fatalln(err)
	}
	serverCert, serverKey, err := store.NewServerCertPair(cert.AltNames{
		IPs: []net.IP{net.ParseIP("127.0.0.2")},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.Write("tls", serverCert, serverKey)
	if err != nil {
		log.Fatalln(err)
	}
	clientCert, clientKey, err := store.NewClientCertPair(cert.AltNames{
		DNSNames: []string{"aadee"},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.Write("aadee", clientCert, clientKey)
	if err != nil {
		log.Fatalln(err)
	}
	// -> <-
	apiserverStore, err := certstore.NewCertStore(fs, crtPath)
	if err != nil {
		log.Fatalln(err)
	}
	if proxy {
		err = apiserverStore.LoadCA("apiserver")
		if err != nil {
			log.Fatalln(err)
		}
	}

	// -----------------------------------------------------------------------------
	rhCACertPool := x509.NewCertPool()
	rhStore, err := certstore.NewCertStore(fs, crtPath)
	if err != nil {
		log.Fatalln(err)
	}
	if proxy {
		err = rhStore.LoadCA("requestheader")
		if err != nil {
			log.Fatalln(err)
		}
		rhCACertPool.AppendCertsFromPEM(rhStore.CACertBytes())
	}
	// -> <-
	cfg := server.Config{
		Address:     "127.0.0.2:8443",
		CACertFiles: []string{
			//store.CertFile("ca"),
		},
		CertFile: store.CertFile("tls"),
		KeyFile:  store.KeyFile("tls"),
	}
	if proxy {
		cfg.CACertFiles = append(cfg.CACertFiles, apiserverStore.CertFile("ca"))
		cfg.CACertFiles = append(cfg.CACertFiles, rhStore.CertFile("ca"))
	}
	srv := server.NewGenericServer(cfg)

	r := mux.NewRouter()
	r.HandleFunc("/animal/{resource}", func(w http.ResponseWriter, r *http.Request) {
		user := "system:anonymous"
		src := "-"
		if len(r.TLS.PeerCertificates) > 0 { // client TLS was used
			opts := x509.VerifyOptions{
				Roots:     rhCACertPool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			if _, err := r.TLS.PeerCertificates[0].Verify(opts); err != nil {
				user = r.TLS.PeerCertificates[0].Subject.CommonName // user name from client cert
				src = "Client-Cert-CN"
			} else {
				user = r.Header.Get("X-Remote-User") // user name from header value passed by apiserver
				src = "X-Remote-User"
			}
		}

		vars := mux.Vars(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Resource: %v requested by user[%s]=%s\n", vars["resource"], src, user)
	})
	r.HandleFunc("/", handler)
	srv.ListenAndServe(r)
}
