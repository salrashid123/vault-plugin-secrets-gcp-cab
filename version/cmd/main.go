package main

import (
	"fmt"
	"log"
	"os"

	"github.com/salrashid123/vault-plugin-secrets-gcp-cab/version"
)

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		log.Fatal("missing argument")
	}

	switch args[0] {
	case "name":
		fmt.Printf("%s", version.Name)
	case "version":
		fmt.Printf("%s", version.Version)
	default:
		log.Fatalf("unknown arg %q", args[0])
	}
}
