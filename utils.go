package main

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
