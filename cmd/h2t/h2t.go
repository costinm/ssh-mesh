package main

import (
	"io"
	"log"
	"net/http"
	"os"
)

// h2t is a minimal tunnel over h2.
// Expects proper certificates ( TODO: document how to add a custom
// CA to the VM roots or use option to specify )
//
// Unfortunately curl doesn't support streaming.
func main() {
	if len(os.Args) == 0 {
		log.Fatal("Args: url")
	}
	url := os.Args[1]
	log.Println("URL:", url)
	r, w := io.Pipe()
	req, _ := http.NewRequest("POST", url, r)

	go func() {
		io.Copy(w, os.Stdin)
	}()

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	io.Copy(os.Stdout, res.Body)
}
