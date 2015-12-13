package main

import (
	"fmt"
	"os"
	"strconv"
)

func CreateExclusive(name string) (*os.File, error) {
	i := 0
	path := name
	for {
		file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
		if err == nil || !os.IsExist(err) {
			return file, err
		}
		i++
		path = name + intToSortedString(i)
	}
}

func intToSortedString(i int) string {
	s := strconv.Itoa(i)
	return fmt.Sprintf("%c%s", 'a'+len(s)-1, s)
}
