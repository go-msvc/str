package str

import (
	"crypto/sha1"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/go-msvc/errors"
)

type PasswordGenerator interface {
	New(requiredLength int) string
	Validate(password string) error
}

type PasswordGeneratorOption interface {
	Apply(pwg *pwg)
}

const (
	CharsLower   = "abcdefghijkmlnopqrstuvwxyz"
	CharsUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	CharsDigits  = "0123456789"
	CharsSymbols = "!@#$%*()_+-={}[]:;\"'<>,./?|\\~`"
)

func NewPasswordGenerator(options ...PasswordGeneratorOption) (PasswordGenerator, error) {
	pwg := pwg{
		charSets: []pwgCharSet{},
	}
	for _, option := range options {
		option.Apply(&pwg)
	}
	if len(pwg.charSets) == 0 {
		//set default charset
		pwg.charSets = []pwgCharSet{{min: 0, max: 0, chars: CharsLower + CharsUpper + CharsDigits + CharsSymbols}}
	}
	return pwg, nil
}

type pwg struct {
	charSets []pwgCharSet
}

func (pwg pwg) New(requiredLength int) string {
	pw := []byte{}

	//start with min from each char set
	charsetNrUsed := make([]int, len(pwg.charSets))
	for charSetIndex, charset := range pwg.charSets {
		for i := 0; i < charset.min; i++ {
			pw = append(pw, charset.chars[rand.Int()%len(charset.chars)])
		}
		charsetNrUsed[charSetIndex] = charset.min
	}

	//fill remaining required length with other charsets
	//until all limited by max len
	i := 0
	n := len(pwg.charSets)
	lastAddIndex := i
	for len(pw) < requiredLength && i < lastAddIndex+n {
		charSet := pwg.charSets[i%n]
		if charsetNrUsed[i] < charSet.max {
			//add from this charset
			pw = append(pw, charSet.chars[rand.Int()%len(charSet.chars)])
			lastAddIndex = i
		}
		i++
	}
	rand.Shuffle(len(pw), func(i, j int) { pw[i], pw[j] = pw[j], pw[i] })
	return string(pw)
}

func (pwg pwg) Validate(password string) error {
	//count nr of chars used from each charset
	charsetNrUsed := make([]int, len(pwg.charSets))
	for _, c := range password {
		for csi, cs := range pwg.charSets {
			if strings.IndexRune(cs.chars, c) >= 0 {
				charsetNrUsed[csi] = charsetNrUsed[csi] + 1
			}
		}
	}
	for csi, cs := range pwg.charSets {
		if cs.min != 0 && charsetNrUsed[csi] < cs.min {
			return errors.Errorf("too few of %s (min %d, you have %d)", cs.chars, cs.min, charsetNrUsed[csi])
		}
		if cs.max != 0 && charsetNrUsed[csi] > cs.max {
			return errors.Errorf("too many of %s (max %d, you have %d)", cs.chars, cs.max, charsetNrUsed[csi])
		}
	}
	return nil
}

type pwgCharSet struct {
	min   int
	max   int
	chars string
}

//min or max == 0 does not apply
func CharSet(min, max int, chars string) PasswordGeneratorOption {
	return pwgoCharSet{min: min, max: max, chars: chars}
}

type pwgoCharSet struct {
	min, max int
	chars    string
}

func (opt pwgoCharSet) Apply(pwg *pwg) {
	if pwg.charSets == nil {
		pwg.charSets = []pwgCharSet{}
	}
	pwg.charSets = append(pwg.charSets, pwgCharSet{
		min:   opt.min,
		max:   opt.max,
		chars: opt.chars,
	})
}

var salt = ""

func init() {
	if envSalt := os.Getenv("PASSWORD_SALT"); envSalt != "" {
		salt = envSalt
	}
}

func PasswordHash(values ...string) string {
	hash := sha1.New()
	for _, s := range values {
		hash.Write([]byte(s))
	}
	return fmt.Sprintf("%X", hash.Sum(nil))
}
