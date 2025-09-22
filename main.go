package main

import (
	"crypto/mlkem"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
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

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	versionLong := flag.Bool("version", false, "print version and exit")
	versionShort := flag.Bool("v", false, "alias for version")
	generatemlkemKey := flag.Bool("genkey", false, "generate a new MLKEM private key (decapsulation key; base64 encoded) and exit")
	showKey := flag.String("showkey", "", "show the public MLKEM key (encapsulation key; base64 encoded) for a given base64 encoded private MLKEM key and exit")
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
		fmt.Printf("PRIVATE_MLKEM_KEY=%s\n", base64.StdEncoding.EncodeToString(key.Bytes()))
		fmt.Printf("TRUSTED_KEYS=%s\n", base64.StdEncoding.EncodeToString(key.EncapsulationKey().Bytes()))
		os.Exit(0)
	}

	if SafeDeref(showKey) != "" {
		privateKeyBytes, err := base64.StdEncoding.DecodeString(*showKey)
		if err != nil {
			log.Panicln("error decoding base64 private MLKEM key: " + err.Error())
		}
		privateKey, err := mlkem.NewDecapsulationKey768(privateKeyBytes)
		if err != nil {
			log.Panicln("error parsing private MLKEM key: " + err.Error())
		}
		publicKey := privateKey.EncapsulationKey()
		fmt.Printf("TRUSTED_KEYS=%s\n", base64.StdEncoding.EncodeToString(publicKey.Bytes()))
		os.Exit(0)
	}

	cfg, err := config.Parse()
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// base64 encode
	myPubKey := cfg.PrivateMLKEMKey.EncapsulationKey().Bytes()
	myPubKeyBase64 := base64.StdEncoding.EncodeToString(myPubKey)
	peerPubKeyBase64 := "" // empty means no peer or untrusted peer
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
					} else if strings.HasPrefix(r, cipherTextPrefix) && peerPubKeyBase64 != "" {
						sharedSecret, err = negotiateSharedKey(cfg, r, roleBackup)
						if err != nil {
							log.Println(err.Error())
						}
						continue
					}
					if peerPubKeyBase64 == "" {
						// set random string as shared secret as peers are untrusted
						log.Println("<-- BACKUP: setting random shared secret as no trusted peer connected")
						sharedSecret = randomString(32)
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
							peerPubKeyBase64 = ""
							continue
						}
						log.Println("--> new peer. reconfiguring roles ...")
						break masterloop
					} else if strings.HasPrefix(message, cipherTextPrefix) && peerPubKeyBase64 == "" {
						log.Println("--> MASTER: received unexpected ciphertext message from untrusted peer")
						continue
					}
				default:
					if peerPubKeyBase64 != "" {
						sharedSecret, err = negotiateSharedKey(cfg, peerPubKeyBase64, roleMaster)
						if err != nil {
							log.Println(err.Error())
						}

						// get key_id and send
						log.Printf("--> MASTER: fetch key_id from %s\n", cfg.KMSURL)
					} else {
						// set random string as shared secret as peers are untrusted
						log.Println("--> MASTER: setting random shared secret as no trusted peer connected")
						sharedSecret = randomString(32)
					}
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
