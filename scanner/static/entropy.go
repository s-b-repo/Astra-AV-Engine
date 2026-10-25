package static

import "math"

// Entropy returns the Shannon entropy of data in bits per byte (0..8).
func Entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	h := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// DefaultEntropyWindow is the sliding-window size used by Profile.
const DefaultEntropyWindow = 256

// HighEntropy is the per-window threshold above which a block is counted as
// compressed/encrypted-looking. 7.0 bits/byte is well above any natural-
// language text or ordinary machine code and below only compressed or
// encrypted data.
const HighEntropy = 7.0

// EntropyProfile summarises a sliding-window pass over a buffer.
type EntropyProfile struct {
	// Window is the window size in bytes.
	Window int `json:"window"`
	// Windows is the number of windows examined.
	Windows int `json:"windows"`
	// HighWindows is how many windows scored above HighEntropy.
	HighWindows int `json:"high_windows"`
	// HighFraction is HighWindows / Windows (0 when no windows).
	HighFraction float64 `json:"high_fraction"`
	Min          float64 `json:"min"`
	Max          float64 `json:"max"`
	Mean         float64 `json:"mean"`
}

// Profile computes entropy over non-overlapping windows of the given size. A
// trailing partial window shorter than half the window size is ignored so a
// short tail cannot skew the minimum.
func Profile(data []byte, window int) EntropyProfile {
	if window <= 0 {
		window = DefaultEntropyWindow
	}
	p := EntropyProfile{Window: window, Min: 8}
	if len(data) == 0 {
		p.Min = 0
		return p
	}
	sum := 0.0
	for off := 0; off < len(data); off += window {
		end := off + window
		if end > len(data) {
			end = len(data)
			if end-off < window/2 && p.Windows > 0 {
				break
			}
		}
		h := Entropy(data[off:end])
		p.Windows++
		sum += h
		if h > HighEntropy {
			p.HighWindows++
		}
		if h < p.Min {
			p.Min = h
		}
		if h > p.Max {
			p.Max = h
		}
	}
	if p.Windows > 0 {
		p.Mean = sum / float64(p.Windows)
		p.HighFraction = float64(p.HighWindows) / float64(p.Windows)
	} else {
		p.Min = 0
	}
	return p
}
