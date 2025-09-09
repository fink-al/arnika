package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/kdf"
	"github.com/arnika-project/arnika/kms"
	wg "github.com/arnika-project/arnika/wireguard"
	"github.com/oklog/ulid/v2"
)

var (
	// allows to set version on build.
	Version string
	// allows to overwrite app name on build.
	APPName string
)

const (
	initPrefix = "init:"
	roleMaster = "master"
	roleBackup = "backup"
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

func getPQCKey(pqcKeyFile string) (string, error) {
	file, err := os.Open(pqcKeyFile)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Scan()
	return scanner.Text(), nil
}

func setPSK(psk string, cfg *config.Config, logPrefix string) error {
	if cfg.UsePQC() {
		log.Println(logPrefix + " key derivation with PQC key enabled")
		pQCKey, err := getPQCKey(cfg.PQCPSKFile)
		if err != nil {
			return err
		}
		psk, err = kdf.DeriveKey(psk, pQCKey)
		if err != nil {
			return err
		}
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
	cfg, err := config.Parse()
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	entropy := rand.New(rand.NewSource(time.Now().UnixNano()))
	ms := ulid.Timestamp(time.Now())
	myID, err := ulid.New(ms, entropy)
	if err != nil {
		log.Fatalf("Failed to generate execution id: %s", err.Error())
	}
	peerID := ""

	interval := cfg.Interval
	done := make(chan bool)
	result := make(chan string)
	kmsAuth := kms.NewClientCertificateAuth(cfg.Certificate, cfg.PrivateKey, cfg.CACertificate)
	kmsServer := kms.NewKMSServer(cfg.KMSURL, int(cfg.KMSHTTPTimeout.Seconds()), kmsAuth)
	go tcpServer(cfg.ListenAddress, result, done)
	go sendHandshake(myID.String(), cfg.ServerAddress)

mainloop:
	for {
		role := IfThenElse(myID.String() > peerID, roleMaster, roleBackup)
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
					if strings.HasPrefix(r, initPrefix) {
						peerID = strings.TrimPrefix(r, initPrefix)
						log.Println("--> new peer. reconfiguring roles ...")
						break backuploop
					}
					log.Println("<-- BACKUP: received key_id " + r)
					// to stuff with key
					key, err := kmsServer.GetKeyByID(r)
					if err != nil {
						log.Println(err.Error())
						time.Sleep(time.Millisecond * 100)
						continue
					}
					err = setPSK(key.GetKey(), cfg, "<-- BACKUP:")
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
					if strings.HasPrefix(message, initPrefix) {
						peerID = strings.TrimPrefix(message, initPrefix)
						log.Println("--> new peer. reconfiguring roles ...")
						break masterloop
					}
				default:
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
					err = setPSK(key.GetKey(), cfg, "--> MASTER:")
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

func sendHandshake(myID string, peerAddress string) {
	err := fmt.Errorf("init")
	for err != nil {
		err = tcpClient(peerAddress, initPrefix+myID)
		time.Sleep(time.Millisecond * 100)
	}
	log.Println("handshake sent to " + peerAddress)
}
