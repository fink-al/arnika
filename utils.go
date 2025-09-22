package main

import (
	"crypto/rand"
	"log"
	"math/big"
	mathrand "math/rand"
)

var charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func IfThenElse[Result any](condition bool, resultA Result, resultB Result) Result {
	if condition {
		return resultA
	}
	return resultB
}

func SafeDeref[T any](s *T) T {
	if s == nil {
		m := GetZero[T]()
		return m
	}
	return *s
}

func GetZero[T any]() T {
	var result T
	return result
}

func fibonacciRecursion(n int) int {
	if n <= 1 {
		return n
	} else if n > 11 {
		return 120
	}
	return fibonacciRecursion(n-1) + fibonacciRecursion(n-2)
}

func randomString(length int) []byte {
	b := make([]byte, length)
	for i := range b {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
		if err != nil {
			log.Println("error generating crypto/rand random string. Fallback to math/rand: " + err.Error())
			random := mathrand.Intn(len(charSet))
			b[i] = charSet[random]
			continue
		}
		b[i] = charSet[j.Int64()]
	}
	return b
}
