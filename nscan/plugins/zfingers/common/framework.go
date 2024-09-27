package common

import (
	"strings"

	"nscan/plugins/zfingers/utils/iutils"
)

const (
	FrameFromDefault = iota
	FrameFromACTIVE
	FrameFromICO
	FrameFromNOTFOUND
	FrameFromGUESS
	FrameFromRedirect
	FrameFromFingerprintHub
	FrameFromWappalyzer
)

var NoGuess bool
var frameFromMap = map[int]string{
	FrameFromDefault:        "finger",
	FrameFromACTIVE:         "active",
	FrameFromICO:            "ico",
	FrameFromNOTFOUND:       "404",
	FrameFromGUESS:          "guess",
	FrameFromRedirect:       "redirect",
	FrameFromFingerprintHub: "fingerprinthub",
	FrameFromWappalyzer:     "wappalyzer",
}

func GetFrameFrom(s string) int {
	switch s {
	case "active":
		return FrameFromACTIVE
	case "404":
		return FrameFromNOTFOUND
	case "ico":
		return FrameFromICO
	case "guess":
		return FrameFromGUESS
	case "redirect":
		return FrameFromRedirect
	case "fingerprinthub":
		return FrameFromFingerprintHub
	case "wappalyzer":
		return FrameFromWappalyzer
	default:
		return FrameFromDefault
	}
}

type Framework struct {
	Name    string       `json:"name"`
	Version string       `json:"version,omitempty"`
	From    int          `json:"-"`
	Froms   map[int]bool `json:"froms,omitempty"`
	Tags    []string     `json:"tags,omitempty"`
	IsFocus bool         `json:"is_focus,omitempty"`
	Data    []byte       `json:"-"`
	Cpe     string       `json:"cpe,omitempty"`
}

func (f *Framework) String() string {
	var s strings.Builder
	if f.IsFocus {
		s.WriteString("focus:")
	}
	s.WriteString(f.Name)

	if f.Version != "" {
		s.WriteString(":" + strings.Replace(f.Version, ":", "_", -1))
	}

	if len(f.Froms) > 1 {
		s.WriteString(":(")
		var froms []string
		for from, _ := range f.Froms {
			froms = append(froms, frameFromMap[from])
		}
		s.WriteString(strings.Join(froms, " "))
		s.WriteString(")")
	} else {
		for from, _ := range f.Froms {
			if from != FrameFromDefault {
				s.WriteString(":")
				s.WriteString(frameFromMap[from])
			}
		}
	}
	return strings.TrimSpace(s.String())
}

func (f *Framework) IsGuess() bool {
	var is bool
	for from, _ := range f.Froms {
		if from == FrameFromGUESS {
			is = true
		} else {
			return false
		}
	}
	return is
}

func (f *Framework) HasTag(tag string) bool {
	for _, t := range f.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

type Frameworks map[string]*Framework

func (fs Frameworks) One() *Framework {
	for _, f := range fs {
		return f
	}
	return nil
}

func (fs Frameworks) List() []*Framework {
	var frameworks []*Framework
	for _, f := range fs {
		frameworks = append(frameworks, f)
	}
	return frameworks
}

func (fs Frameworks) Add(other *Framework) bool {
	other.Name = strings.ToLower(other.Name)
	if frame, ok := fs[other.Name]; ok {
		frame.Froms[other.From] = true
		return false
	} else {
		other.Froms = map[int]bool{other.From: true}
		fs[other.Name] = other
		return true
	}
}

func (fs Frameworks) Merge(other Frameworks) int {
	// name, tag 统一小写, 减少指纹库之间的差异
	var n int
	for _, f := range other {
		f.Name = strings.ToLower(f.Name)
		if frame, ok := fs[f.Name]; ok {
			if frame.Version == "" && f.Version != "" {
				frame.Version = f.Version
			}
			if len(f.Tags) > 0 {
				for i, tag := range f.Tags {
					f.Tags[i] = strings.ToLower(tag)
				}
				frame.Tags = iutils.StringsUnique(append(frame.Tags, f.Tags...))
			}
		} else {
			fs[f.Name] = f
			n += 1
		}
	}
	return n
}

func (fs Frameworks) String() string {
	if fs == nil {
		return ""
	}
	frameworkStrs := make([]string, len(fs))
	i := 0
	for _, f := range fs {
		if NoGuess && f.IsGuess() {
			continue
		}
		frameworkStrs[i] = f.String()
		i++
	}
	return strings.Join(frameworkStrs, "||")
}

func (fs Frameworks) GetNames() []string {
	if fs == nil {
		return nil
	}
	var titles []string
	for _, f := range fs {
		if !f.IsGuess() {
			titles = append(titles, f.Name)
		}
	}
	return titles
}

func (fs Frameworks) IsFocus() bool {
	if fs == nil {
		return false
	}
	for _, f := range fs {
		if f.IsFocus {
			return true
		}
	}
	return false
}

func (fs Frameworks) HasTag(tag string) bool {
	for _, f := range fs {
		if f.HasTag(tag) {
			return true
		}
	}
	return false
}

func (fs Frameworks) HasFrom(from string) bool {
	for _, f := range fs {
		if f.Froms[GetFrameFrom(from)] {
			return true
		}
	}
	return false
}
