package str

import "regexp"

const identifierPattern = `[a-zA-Z]([a-zA-Z0-9_]*[a-zA-Z0-9])*`

var identifierRegex = regexp.MustCompile("^" + identifierPattern + "$")

func IsIdentifier(s string) bool {
	return identifierRegex.MatchString(s)
}
