package weburl

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// Punycode (RFC 3492) encoding of one host label, for the ASCII form of an
// internationalized host name. Only encoding is needed: a receiver stores
// and compares the ASCII form. The label is lowercased first; the full
// UTS #46 mapping (width folding, normalization) is not applied, so two
// spellings that differ only in such a mapping keep different ASCII forms.

const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
	maxLabelBytes = 63
)

var errPunycode = errors.New("label cannot be encoded")

func pcAdapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}

func pcDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

// punycodeLabel returns the ASCII form of one lowercase label: the label
// itself when it is ASCII, else "xn--" and its Punycode encoding.
func punycodeLabel(label string) (string, error) {
	ascii := true
	for i := 0; i < len(label); i++ {
		if label[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return label, nil
	}
	if !utf8.ValidString(label) {
		return "", errPunycode
	}
	runes := []rune(label)
	var out strings.Builder
	for _, r := range runes {
		if r < utf8.RuneSelf {
			out.WriteByte(byte(r))
		}
	}
	b := out.Len()
	h := b
	if b > 0 {
		out.WriteByte('-')
	}
	n, delta, bias := pcInitialN, 0, pcInitialBias
	for h < len(runes) {
		m := int(^uint(0) >> 1)
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		if (m - n) > (int(^uint(0)>>1)-delta)/(h+1) {
			return "", errPunycode
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range runes {
			if int(r) < n {
				delta++
			}
			if int(r) == n {
				q := delta
				for k := pcBase; ; k += pcBase {
					t := k - bias
					if t < pcTMin {
						t = pcTMin
					} else if t > pcTMax {
						t = pcTMax
					}
					if q < t {
						break
					}
					out.WriteByte(pcDigit(t + (q-t)%(pcBase-t)))
					q = (q - t) / (pcBase - t)
				}
				out.WriteByte(pcDigit(q))
				bias = pcAdapt(delta, h+1, h == b)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	s := "xn--" + out.String()
	if len(s) > maxLabelBytes {
		return "", errPunycode
	}
	return s, nil
}
