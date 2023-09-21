package analyze

import (
	"bufio"
	"golang.org/x/exp/slices"
	"os"
	"strings"
)

func checkIfHostStringIsContained(host string, hostSlice []string, tld string) bool {
	parts := strings.Split(host, ".")
	if tld != "" {
		tldParts := strings.Split(tld, ".")
		if len(parts) > 0 && (len(parts) == len(tldParts)+1) {
			if slices.Contains(hostSlice, parts[0]) {
				return true
			}
		}
	} else {
		if len(parts) > 0 {
			if slices.Contains(hostSlice, parts[0]) {
				return true
			}
		}
	}

	return false
}

func indexAt(s, sep string, n int) int {
	if n >= 0 {
		if n < len(s) {
			idx := strings.Index(s[n:], sep)
			if idx > -1 {
				idx += n
			}
			return idx
		}
	}

	return -1
}

func lastIndexAt(s, sep string, n int) int {
	if n >= 0 {
		if n < len(s) {
			idx := strings.LastIndex(s[n:], sep)
			if idx > -1 {
				idx += n
			}
			return idx
		}
	}

	return -1
}

func WriteToFileInProject(filename string, data string) {
	writeFile, err := os.Create(filename)
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	dataWriter := bufio.NewWriter(writeFile)

	if err != nil {
		log.Error(err)
	}
	dataWriter.WriteString(data)
	dataWriter.Flush()
	writeFile.Close()
}

func AppendIfMissing(slice []string, key string) []string {
	for _, element := range slice {
		if element == key {
			log.Debugf("%s already exists in the slice.", key)
			return slice
		}
	}
	return append(slice, key)
}
