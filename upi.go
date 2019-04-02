package vmu

import (
	"unicode"
)

var upibuf = make([]byte, UPILen)

func UserInfo(upi [UPILen]byte) []byte {
	return userInfo(upibuf, upi)
}

func userInfo(buf []byte, upi [UPILen]byte) []byte {
	var n int
	for i := 0; i < UPILen; i++ {
		keep, done := shouldKeepRune(rune(upi[i]))
		if done {
			break
		}
		if !keep {
			continue
		}
		buf[n] = upi[i]
		n++
	}
	return buf[:n]
}

func shouldKeepRune(r rune) (bool, bool) {
	if r == 0 {
		return false, true
	}
	if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
		return true, false
	}
	return false, true
}
