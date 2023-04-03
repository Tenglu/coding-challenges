package main

import (
	"github.com/fiskaly/coding-challenges/signing-service-challenge/api"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
	"log"
)

const (
	ListenAddress = ":8080"
)

func main() {
	server := api.NewServer(ListenAddress, persistence.NewInMemoryDeviceRepository())

	if err := server.Run(); err != nil {
		log.Fatal("Could not start server on ", ListenAddress)
	}
}
