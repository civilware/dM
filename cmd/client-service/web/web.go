package web

import (
	"log"
	"net/http"
)

type Website struct {
	Enabled  bool
	Port     string
	SSL      bool
	SSLPort  string
	CertFile string
	KeyFile  string
}

// Keep website running
func StartWeb(cfg *Website) {
	fileServer := http.FileServer(http.Dir("./site"))
	http.Handle("/", fileServer)

	// If SSL is enabled, configure for SSL and HTTP. Else just run HTTP
	if cfg.SSL {
		go func() {
			log.Printf("[Website] Starting website at localhost:%v\n", cfg.Port)
			addr := ":" + cfg.Port
			err := http.ListenAndServe(addr, nil)
			if err != nil {
				log.Printf("[Website] Error starting http server at localhost:%v", addr)
				log.Fatal(err)
			}
		}()

		log.Printf("[Website] Starting SSL website at localhost:%v\n", cfg.SSLPort)

		addr := ":" + cfg.SSLPort
		err := http.ListenAndServeTLS(addr, cfg.CertFile, cfg.KeyFile, nil)
		if err != nil {
			log.Printf("[Website] Error starting https server at localhost:%v", addr)
			log.Fatal(err)
		}
	} else {
		log.Printf("[Website] Starting website at localhost:%v\n", cfg.Port)

		addr := ":" + cfg.Port
		err := http.ListenAndServe(addr, nil)
		if err != nil {
			log.Printf("[Website] Error starting http server at localhost:%v", addr)
			log.Fatal(err)
		}
	}
}
