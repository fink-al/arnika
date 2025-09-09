package main

import (
	"bufio"
	"crypto/mlkem"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/kdf"
	"github.com/arnika-project/arnika/kms"
	wg "github.com/arnika-project/arnika/wireguard"
)

var (
	// allows to set version on build.
	Version string
	// allows to overwrite app name on build.
	APPName string
)

const (
	pubKeyExchangePrefix = "init:"
	cipherTextPrefix     = "ct:"
	roleMaster           = "master"
	roleBackup           = "backup"
)

func handleServerConnection(c net.Conn, result chan string) {
	// Check that c is not nil.
	if c == nil {
		panic("received nil connection")
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from panic:", r)
		}
	}()
	for {
		// scan message
		scanner := bufio.NewScanner(c)
		// Check that scanner is not nil.
		if scanner == nil {
			panic("received nil scanner")
		}
		for scanner.Scan() {
			msg := scanner.Text()
			result <- msg
			_, err := c.Write([]byte("ACK" + "\n"))
			if err != nil { // Handle the write error
				fmt.Println("Failed to write to connection:", err)
				break
			}
		}
		if errRead := scanner.Err(); errRead != nil { // Handle the read error
			if errRead == io.EOF { // Handle EOF
				fmt.Println("Connection closed by remote host.")
				break
			}
			// expected
			// fmt.Println("Failed to read from connection:", errRead)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func tcpServer(url string, result chan string, done chan bool) {
	// defer close(done)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	go func() {
		<-quit
		log.Println("TCP Server shutdown")
		close(done)
	}()
	log.Printf("TCP Server listening on %s\n", url)
	ln, err := net.Listen("tcp", url)
	if err != nil {
		log.Panicln(err.Error())
		return
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Println(err.Error())
				break
			}
			go handleServerConnection(c, result)
			time.Sleep(100 * time.Millisecond)
		}
	}()
	<-done
	err = ln.Close()
	if err != nil {
		log.Println(err.Error())
	}
}

func tcpClient(url, data string) error {
	if url == "" {
		return fmt.Errorf("url is empty")
	}
	if data == "" {
		return fmt.Errorf("data is empty")
	}
	c, err := net.DialTimeout("tcp", url, time.Millisecond*100)
	if err != nil {
		return err
	}
	defer func() {
		if c != nil {
			c.Close()
		}
	}()
	_, err = c.Write([]byte(data + "\n"))
	if err != nil {
		return err
	}
	return c.SetDeadline(time.Now().Add(time.Millisecond * 100))
}

func setPSK(psk string, cfg *config.Config, logPrefix string, sharedSecret []byte) error {
	var err error
	psk, err = kdf.DeriveKey(psk, base64.StdEncoding.EncodeToString(sharedSecret))
	if err != nil {
		return err
	}
	log.Println(logPrefix + " configure wireguard interface")
	wireguard, err := wg.NewWireGuardHandler()
	if err != nil {
		return err
	}
	return wireguard.SetKey(cfg.WireGuardInterface, cfg.WireguardPeerPublicKey, psk)
}

func fibonacciRecursion(n int) int {
	if n <= 1 {
		return n
	} else if n > 11 {
		return 120
	}
	return fibonacciRecursion(n-1) + fibonacciRecursion(n-2)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	versionLong := flag.Bool("version", false, "print version and exit")
	versionShort := flag.Bool("v", false, "alias for version")
	generatemlkemKey := flag.Bool("genkey", false, "generate a new MLKEM private key (decapsulation key; base64 encoded) and exit")
	flag.Parse()
	if *versionShort || *versionLong {
		fmt.Printf("%s version %s\n", APPName, Version)
		os.Exit(0)
	}
	help := flag.Bool("help", false, "print usage and exit")
	flag.Parse()
	if *help {
		flag.Usage()
		os.Exit(0)
	}
	if SafeDeref(generatemlkemKey) {
		key, err := mlkem.GenerateKey768()
		if err != nil {
			log.Panicln(err.Error())
		}
		fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(key.Bytes()))
		os.Exit(0)
	}

	cfg, err := config.Parse()
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// base64 encode
	myPubKey := cfg.PrivateMLKEMKey.EncapsulationKey().Bytes()
	myPubKeyBase64 := base64.StdEncoding.EncodeToString(myPubKey)
	peerPubKeyBase64 := ""
	sharedSecret := []byte{}

	interval := cfg.Interval
	done := make(chan bool)
	result := make(chan string)
	kmsAuth := kms.NewClientCertificateAuth(cfg.Certificate, cfg.PrivateKey, cfg.CACertificate)
	kmsServer := kms.NewKMSServer(cfg.KMSURL, int(cfg.KMSHTTPTimeout.Seconds()), kmsAuth)
	go tcpServer(cfg.ListenAddress, result, done)
	go sendHandshakeMessage(pubKeyExchangePrefix, myPubKeyBase64, cfg.ServerAddress)

mainloop:
	for {
		role := IfThenElse(myPubKeyBase64 > peerPubKeyBase64, roleMaster, roleBackup)
		if err != nil {
			log.Println(err.Error())
		}
		switch role {
		case roleBackup:
		backuploop:
			for {
				select {
				case <-done:
					break mainloop
				case r := <-result:
					if strings.HasPrefix(r, pubKeyExchangePrefix) {
						peerPubKeyBase64 = strings.TrimPrefix(r, pubKeyExchangePrefix)
						if !slices.Contains(cfg.TrustedKeys, peerPubKeyBase64) {
							log.Printf("<-- BACKUP: untrusted peer: %s\n", peerPubKeyBase64)
							peerPubKeyBase64 = ""
							break backuploop
						}
						log.Println("--> new peer. reconfiguring roles ...")
						break backuploop
					} else if strings.HasPrefix(r, cipherTextPrefix) {
						sharedSecret, err = negotiateSharedKey(cfg, r, roleBackup)
						if err != nil {
							log.Println(err.Error())
						}
						continue
					}
					log.Println("<-- BACKUP: received key_id " + r)
					// to stuff with key
					key, err := kmsServer.GetKeyByID(r) // TODO: make kms secondary/optional as input for key derivation
					if err != nil {
						log.Println(err.Error())
						time.Sleep(time.Millisecond * 100)
						continue
					}
					err = setPSK(key.GetKey(), cfg, "<-- BACKUP:", sharedSecret)
					if err != nil {
						log.Println(err.Error())
					}
				}
			}
		case roleMaster:
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			i := 20
		masterloop:
			for {
				select {
				case <-done:
					break mainloop
				case message := <-result:
					if strings.HasPrefix(message, pubKeyExchangePrefix) {
						peerPubKeyBase64 = strings.TrimPrefix(message, pubKeyExchangePrefix)
						if !slices.Contains(cfg.TrustedKeys, peerPubKeyBase64) {
							log.Printf("--> MASTER: untrusted peer: %s\n", peerPubKeyBase64)
							continue
						}
						log.Println("--> new peer. reconfiguring roles ...")
						break masterloop
					}
				default:
					sharedSecret, err = negotiateSharedKey(cfg, peerPubKeyBase64, roleMaster)
					if err != nil {
						log.Println(err.Error())
					}

					// get key_id and send
					log.Printf("--> MASTER: fetch key_id from %s\n", cfg.KMSURL)

					key, err := kmsServer.GetNewKey()
					if err != nil {
						log.Println(err.Error())
						time.Sleep(time.Second * time.Duration(fibonacciRecursion(i/10)))
						i++
						continue
					}
					i = 20
					log.Printf("--> MASTER: send key_id to %s\n", cfg.ServerAddress)
					err = tcpClient(cfg.ServerAddress, key.GetID())
					if err != nil {
						log.Println(err.Error())
					}
					err = setPSK(key.GetKey(), cfg, "--> MASTER:", sharedSecret)
					if err != nil {
						log.Println(err.Error())
					}
				}
				select {
				case <-done:
					break mainloop
				case <-ticker.C:
				}
			}
		}
	}
}

func sendHandshakeMessage(prefix, message string, peerAddress string) {
	err := fmt.Errorf("init")
	for err != nil {
		err = tcpClient(peerAddress, prefix+message)
		time.Sleep(time.Millisecond * 100)
	}
	log.Println("handshake sent to " + peerAddress)
}

func negotiateSharedKey(cfg *config.Config, input string, role string) ([]byte, error) {
	if role == roleMaster {
		log.Println("--> MASTER: MLKEM: negotiate shared key")
		if input == "" {
			return nil, nil // startup; no backup yet
		}
		peerPubKeyBytes, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			return nil, err
		}
		peerKey, err := mlkem.NewEncapsulationKey768(peerPubKeyBytes)
		if err != nil {
			return nil, err
		}
		sharedSecret, cipherText := peerKey.Encapsulate()
		sendHandshakeMessage(cipherTextPrefix, base64.StdEncoding.EncodeToString(cipherText), cfg.ServerAddress)
		return sharedSecret, nil
	}
	log.Println("<-- BACKUP: MLKEM: negotiate shared key")
	if strings.HasPrefix(input, cipherTextPrefix) {
		cipherTextBase64 := strings.TrimPrefix(input, cipherTextPrefix)
		cipherText, err := base64.StdEncoding.DecodeString(cipherTextBase64)
		if err != nil {
			return nil, err
		}
		sharedSecret, err := cfg.PrivateMLKEMKey.Decapsulate(cipherText)
		if err != nil {
			return nil, err
		}
		return sharedSecret, nil
	} else {
		return nil, fmt.Errorf("invalid message format")
	}
}
