package main

func IfThenElse[Result any](condition bool, resultA Result, resultB Result) Result {
	if condition {
		return resultA
	}
	return resultB
}
