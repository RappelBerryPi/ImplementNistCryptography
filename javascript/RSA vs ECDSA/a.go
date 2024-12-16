package main

import (
	"net/http"
)

func main() {
	http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", http.FileServer(http.Dir(".")))
}
