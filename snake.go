package str

import "regexp"

const snakePattern = `[a-z]([a-z0-9_]*[a-z0-9])*`

var snakeRegex = regexp.MustCompile("^" + snakePattern + "$")

func IsSnake(s string) bool {
	return snakeRegex.MatchString(s)
}
