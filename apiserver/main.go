package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/obaydullahmhs/k8s-extended-apiserver/lib/certstore"
	"github.com/obaydullahmhs/k8s-extended-apiserver/lib/server"
	"github.com/spf13/afero"
	"io"
	"k8s.io/client-go/util/cert"
	"log"
	"net"
	"net/http"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "OK")
}

var crtPath = "/home/appscodepc/go/src/github.com/obaydullahmhs/k8s-extended-apiserver/certs"

func main() {
	var proxy = false
	flag.BoolVar(&proxy, "send-proxy-request", proxy, "forward requests to animal extended apiserver")
	flag.Parse()

	fs := afero.NewOsFs()
	store, err := certstore.NewCertStore(fs, crtPath)
	if err != nil {
		log.Fatalln(err)
	}
	err = store.NewCA("apiserver")
	if err != nil {
		log.Fatalln(err)
	}
	serverCert, serverKey, err := store.NewServerCertPair(cert.AltNames{
		IPs: []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.Write("tls", serverCert, serverKey)
	if err != nil {
		log.Fatalln(err)
	}
	clientCert, clientKey, err := store.NewClientCertPair(cert.AltNames{
		DNSNames: []string{"obay"},
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = store.Write("obay", clientCert, clientKey)
	if err != nil {
		log.Fatalln(err)
	}
	// -> generate client certifiacte for extended server <-

	rhStore, err := certstore.NewCertStore(fs, crtPath)
	if err != nil {
		log.Fatalln(err)
	}
	err = rhStore.InitCA("requestheader")
	if err != nil {
		log.Fatalln(err)
	}

	rhClientCert, rhClientKey, err := rhStore.NewClientCertPair(cert.AltNames{
		DNSNames: []string{"apiserver"}, // because apiserver is making the calls to animal extended api server
	})
	if err != nil {
		log.Fatalln(err)
	}
	err = rhStore.Write("apiserver", rhClientCert, rhClientKey)
	if err != nil {
		log.Fatalln(err)
	}
	rhCert, err := tls.LoadX509KeyPair(rhStore.CertFile("apiserver"), rhStore.KeyFile("apiserver"))
	if err != nil {
		log.Fatalln(err)
	}
	// -> <-
	easCACertPool := x509.NewCertPool()
	if proxy {
		easStore, err := certstore.NewCertStore(fs, crtPath)
		if err != nil {
			log.Fatalln(err)
		}
		err = easStore.LoadCA("animal")
		if err != nil {
			log.Fatalln(err)
		}
		easCACertPool.AppendCertsFromPEM(easStore.CACertBytes())
	}
	// -> <-
	cfg := server.Config{
		Address: "127.0.0.1:8443",
		CACertFiles: []string{
			store.CertFile("ca"),
		},
		CertFile: store.CertFile("tls"),
		KeyFile:  store.KeyFile("tls"),
	}
	srv := server.NewGenericServer(cfg)

	r := mux.NewRouter()
	r.HandleFunc("/api/{resource}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Resource: %v\n", vars["resource"])
	})
	if proxy {
		r.HandleFunc("/animal/{resource}", func(w http.ResponseWriter, r *http.Request) {
			tr := &http.Transport{
				MaxIdleConnsPerHost: 10,
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{rhCert},
					RootCAs:      easCACertPool,
				},
			}
			client := http.Client{
				Transport: tr,
				Timeout:   time.Duration(30 * time.Second),
			}

			u := *r.URL
			u.Scheme = "https"
			u.Host = "127.0.0.2:8443"
			fmt.Printf("forwarding request to %v\n", u.String())

			req, _ := http.NewRequest(r.Method, u.String(), nil)
			if len(r.TLS.PeerCertificates) > 0 {
				req.Header.Set("X-Remote-User", r.TLS.PeerCertificates[0].Subject.CommonName)
			}

			resp, err := client.Do(req)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "error: %v\n", err.Error())
				return
			}
			defer resp.Body.Close()

			w.WriteHeader(http.StatusOK)
			io.Copy(w, resp.Body)
		})
	}
	r.HandleFunc("/", handler)
	srv.ListenAndServe(r)
}
