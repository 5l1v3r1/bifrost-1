package nginx

import (
	"regexp"
)

type Key struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (k *Key) String() []string {
	if k.Value == "" {
		return []string{k.Name + ";\n"}
		//} else if !inString(k.Value, "\"") && (inString(k.Value, ";") || inString(k.Value, "#")) {
		//	return []string{k.Name + " \"" + k.Value + "\";\n"}
	}
	return []string{k.Name + " " + k.Value + ";\n"}
}

func (k *Key) QueryAll(kw KeyWords) (parsers []Parser) {
	if !kw.IsReg {
		if kw.Type == TypeKey && kw.Name == k.Name && (kw.Value == k.Value || kw.Value == `*`) {
			parsers = append(parsers, k)
		} else {
			parsers = nil
		}
	} else {

		if kw.Type == TypeKey && regexp.MustCompile(kw.Name).MatchString(k.Name) && regexp.MustCompile(kw.Value).MatchString(k.Value) {
			parsers = append(parsers, k)
		} else {
			parsers = nil
		}
	}
	return
}

func (k *Key) Query(kw KeyWords) (parser Parser) {
	if !kw.IsReg {
		if kw.Type == TypeKey && kw.Name == k.Name && (kw.Value == k.Value || kw.Value == `*`) {
			parser = k
		} else {
			parser = nil
		}
	} else {

		if kw.Type == TypeKey && regexp.MustCompile(kw.Name).MatchString(k.Name) && regexp.MustCompile(kw.Value).MatchString(k.Value) {
			parser = k
		} else {
			parser = nil
		}
	}
	return
}

func (k *Key) BitSize(_ Order, _ int) byte {
	return 0
}

func (k *Key) BitLen(_ Order) int {
	return 0
}

func (k *Key) Size(_ Order) int {
	return 0
}

//func inString(str string, s string) bool {
//	if strings.Index(str, s) >= 0 {
//		return true
//	}
//	return false
//}

func NewKey(name, value string) *Key {
	return &Key{
		Name:  name,
		Value: value,
	}
}