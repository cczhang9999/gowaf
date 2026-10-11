package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// usage: sshtry <host:port> <user> <password>
// Exits 0 when the SSH handshake (i.e. password authentication) succeeds.
func main() {
	if len(os.Args) != 4 {
		fmt.Println("usage: sshtry <host:port> <user> <password>")
		os.Exit(2)
	}
	cfg := &ssh.ClientConfig{
		User:            os.Args[2],
		Auth:            []ssh.AuthMethod{ssh.Password(os.Args[3])},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", os.Args[1], cfg)
	if err != nil {
		fmt.Println("AUTH FAILED:", err)
		os.Exit(1)
	}
	defer client.Close()
	fmt.Println("AUTH OK")
}
