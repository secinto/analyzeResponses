package analyze

import (
	"strings"
)

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
