package main

import (
	"io"
	"log"
	"net/http"
	"os"
)

// h2t is a minimal TCP tunnel over h2.
//
// Expects proper certificates ( TODO: document how to add a custom
// CA to the VM roots or use option to specify )
//
// Unfortunately curl doesn't support streaming - if it did, this could
// be done with a curl command.
func main() {

	if len(os.Args) == 0 {
		log.Fatal("Args: url")
	}

	url := os.Args[1]

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
