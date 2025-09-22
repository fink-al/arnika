package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
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
