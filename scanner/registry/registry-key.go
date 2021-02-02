// +build windows

package registry

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/spyre-project/spyre/config"
	"github.com/spyre-project/spyre/log"
	"github.com/spyre-project/spyre/report"
	"github.com/spyre-project/spyre/scanner"
	"golang.org/x/sys/windows/registry"
	"www.velocidex.com/golang/regparser"

	"regexp"
	"strings"
)

func init() { scanner.RegisterSystemScanner(&systemScanner{}) }

type systemScanner struct {
	iocs []eventIOC
}

type eventIOC struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Type        int    `json:"type"`
	//type:
	// 0 == key exist
	// 1 == name exist
	// 2 == name contains exist
	// 3 == key value Contains
	// 4 == key value regex match
	// 5 == key value Contains (without name)
	// 6 == key value regex match (without name)
}

type iocFile struct {
	Keys []eventIOC `json:"registry-keys"`
}

func (s *systemScanner) Name() string { return "Registry-Key" }

func (s *systemScanner) Init() error {
	iocFiles := config.IocFiles
	if len(iocFiles) == 0 {
		iocFiles = []string{"ioc.json"}
	}
	for _, file := range iocFiles {
		var current iocFile
		if err := config.ReadIOCs(file, &current); err != nil {
			log.Error(err.Error())
		}
		for _, ioc := range current.Keys {
			s.iocs = append(s.iocs, ioc)
		}
	}
	return nil
}

func ukeyCheck(key string, name string, valuex string, typex int, desc string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", registry.QUERY_VALUE)
	if err != nil {
		log.Debugf("Can't open registry key ProfileList : %s", key)
		return
	}
	defer k.Close()
	val, err := getRegistryValueAsString(k, "ProfilesDirectory")
	if err != nil {
		log.Debugf("Error to open ProfilesDirectory : %s", err)
		return
	}
	m1 := regexp.MustCompile(`%([^\%]+)%`)
	val = m1.ReplaceAllString(val, "$${$1}")
	val = os.ExpandEnv(val)
	files, err := ioutil.ReadDir(val)
	if err != nil {
		log.Debugf("Error open user profils directory : %s", err)
	}
	for _, f := range files {
		if _, err := os.Stat(val + "\\" + f.Name() + "\\NTUSER.dat"); err == nil {
			//fr, err := os.OpenFile(val+"\\"+f.Name()+"\\NTUSER.dat", os.O_RDONLY, 0600)
			fr, err := os.Open(val + "\\" + f.Name() + "\\NTUSER.dat")
			if err != nil {
				log.Debugf("Error open base NTUSER: %s -- %s", val+"\\"+f.Name()+"\\NTUSER.dat", err)
				continue
			}
			uregistry, err := regparser.NewRegistry(fr)
			if err != nil {
				log.Debugf("Error load base NTUSER: %s -- %s", val+"\\"+f.Name()+"\\NTUSER.dat", err)
				continue
			}
			xkeys := uregistry.OpenKey(key)
			if xkeys == nil {
				log.Debugf("Can't open registry key: %s in %s", key, val+"\\"+f.Name()+"\\NTUSER.dat")
				continue
			}
			if typex == 0 {
				//key name exist
				report.AddStringf("Found registry on user %s [%s] -- Date %v -- IOC for %s", f.Name(), key, xkeys.LastWriteTime(), desc)
				continue
			}
			for _, vals := range xkeys.Values() {
				namex := fmt.Sprintf("%s", vals.ValueName())
				val := fmt.Sprintf("%s", vals.ValueData())
				//log.Noticef("Registre val %s : %#v\n", vals.ValueName(), vals.ValueData())
				if typex == 1 && namex == name {
					//key name exist
					report.AddStringf("Found registry on user %s [%s]%s -> %s -- Date %v -- IOC for %s", f.Name(), key, namex, val, xkeys.LastWriteTime(), desc)
					continue
				}
				if typex == 2 && strings.Contains(namex, name) {
					// 2 == name contains exist
					report.AddStringf("Found registry on user %s [%s]%s -> %s -- Date %v -- IOC for %s", f.Name(), key, namex, val, xkeys.LastWriteTime(), desc)
					continue
				}
				if typex == 3 && namex == name {
					//value Contains
					res := strings.Contains(val, valuex)
					if res {
						report.AddStringf("Found registry on user %s [%s]%s -> %s -- Date %v -- IOC for %s", f.Name(), key, namex, val, xkeys.LastWriteTime(), desc)
						continue
					}
				}
				if typex == 4 && namex == name {
					matched, err := regexp.MatchString(valuex, val)
					if err != nil {
						log.Noticef("Error regexp : %s", err)
						continue
					}
					if matched {
						report.AddStringf("Found registry on user %s [%s]%s -> %s -- Date %v -- IOC for %s", f.Name(), key, namex, val, xkeys.LastWriteTime(), desc)
						continue
					}
					continue
				}
				if typex == 5 {
					//value Contains
					res := strings.Contains(val, valuex)
					if res {
						report.AddStringf("Found registry on user %s [%s]%s -> %s -- Date %v -- IOC for %s", f.Name(), key, namex, val, xkeys.LastWriteTime(), desc)
						continue
					}
					continue
				}
				if typex == 6 {
					matched, err := regexp.MatchString(valuex, val)
					if err != nil {
						log.Debugf("Error regexp : %s", err)
						continue
					}
					if matched {
						report.AddStringf("Found registry on user %s [%s]%s -> %s -- Date %v -- IOC for %s", f.Name(), key, namex, val, xkeys.LastWriteTime(), desc)
						continue
					}
					continue
				}
			}
		}
	}
}

func keyCheck(key string, name string, valuex string, typex int, desc string, baseHandle registry.Key) {
	log.Debugf("Looking for %s %s ...", key, name)
	if baseHandle == 0xbad {
		log.Debugf("Unknown registry key prefix: %s", key)
		return
	}
	//
	var err error
	k, err := registry.OpenKey(baseHandle, key, registry.QUERY_VALUE)
	if err != nil {
		log.Debugf("Can't open registry key : %s", key)
		return
	}
	defer k.Close()
	var datem = ""
	ki, err := k.Stat()
	if err == nil {
		time_tmp := ki.ModTime()
		if date_tmp != nil {
			datem = date_tmp.String()
		}
	}
	if typex == 0 {
		//key name exist
		report.AddStringf("Found registry [%s] -- Date %s -- IOC for %s", key, datem, desc)
		return
	}
	switch typex {
	case
		2,
		5,
		6:
		params, err := k.ReadValueNames(0)
		if err != nil {
			log.Debugf("Can't ReadSubKeyNames : %s %#v", key, err)
			return
		}
		for _, param := range params {
			if typex == 2 {
				res := strings.Contains(param, name)
				if res {
					report.AddStringf("Found registry [%s]%s -- Date %s -- IOC for %s", key, param, datem, desc)
					return
				}
			}
			if typex == 5 {
				val, err := getRegistryValueAsString(k, param)
				if err != nil {
					log.Debugf("Error : %s", err)
					continue
				}
				res := strings.Contains(val, valuex)
				if res {
					report.AddStringf("Found registry [%s]%s -> %s -- Date %s --IOC for %s", key, param, val, datem, desc)
					return
				}
			}
			if typex == 6 {
				val, err := getRegistryValueAsString(k, param)
				if err != nil {
					log.Debugf("Error : %s", err)
					continue
				}
				matched, err := regexp.MatchString(valuex, val)
				if err != nil {
					log.Noticef("Error regexp for key %s: %s", key, err)
					return
				}
				if matched {
					report.AddStringf("Found registry [%s]%s -> %s -- Date %s -- IOC for %s", key, param, val, datem, desc)
					return
				}
			}
		}
		return
	}
	val, err := getRegistryValueAsString(k, name)
	if err != nil {
		log.Debugf("Error : %s", err)
		return
	}
	if typex == 1 {
		//key name exist
		report.AddStringf("Found registry [%s]%s -- Date %s -- IOC for %s", key, name, datem, desc)
		return
	}
	if typex == 3 {
		//value Contains
		res := strings.Contains(val, valuex)
		if res {
			report.AddStringf("Found registry [%s]%s -> %s -- Date %s -- IOC for %s", key, name, val, datem, desc)
			return
		}
		return
	}
	if typex == 4 {
		matched, err := regexp.MatchString(valuex, val)
		if err != nil {
			log.Noticef("Error regexp for key %s: %s", key, err)
			return
		}
		if matched {
			report.AddStringf("Found registry [%s]%s -> %s -- Date %s -- IOC for %s", key, name, val, datem, desc)
			return
		}
		return
	}
	// settings[param] = val
	// test val according by type
	return
}

func getRegistryValueAsString(key registry.Key, subKey string) (string, error) {
	valString, _, err := key.GetStringValue(subKey)
	if err == nil {
		return valString, nil
	}
	valStrings, _, err := key.GetStringsValue(subKey)
	if err == nil {
		return strings.Join(valStrings, "\n"), nil
	}
	valBinary, _, err := key.GetBinaryValue(subKey)
	if err == nil {
		return string(valBinary), nil
	}
	valInteger, _, err := key.GetIntegerValue(subKey)
	if err == nil {
		return strconv.FormatUint(valInteger, 10), nil
	}
	return "", errors.New("Can't get type for sub key " + subKey)
}

func (s *systemScanner) Scan() error {
	for _, ioc := range s.iocs {
		var key string
		var baseHandle registry.Key = 0xbad
		var hkcu bool = false
		for prefix, handle := range map[string]registry.Key{
			"HKEY_CLASSES_ROOT":     registry.CLASSES_ROOT,
			"HKEY_CURRENT_USER":     registry.CURRENT_USER,
			"HKCU":                  registry.CURRENT_USER,
			"HKEY_LOCAL_MACHINE":    registry.LOCAL_MACHINE,
			"HKLM":                  registry.LOCAL_MACHINE,
			"HKEY_USERS":            registry.USERS,
			"HKU":                   registry.USERS,
			"HKEY_PERFORMANCE_DATA": registry.PERFORMANCE_DATA,
			"HKEY_CURRENT_CONFIG":   registry.CURRENT_CONFIG,
		} {
			if strings.HasPrefix(ioc.Key, prefix+`\`) {
				if strings.Contains(prefix, "HKEY_CURRENT_USER") || strings.Contains(prefix, "HKCU") {
					hkcu = true
				}
				baseHandle = handle
				key = ioc.Key[len(prefix)+1:]
				break
			}
		}
		if strings.Contains(key, "**") {
			//key with wildcard
			ckey := strings.Split(key, "**")
			k, err := registry.OpenKey(baseHandle, ckey[0], registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
			if err != nil {
				log.Noticef("Can't open registry key : %s", key)
				continue
			}
			defer k.Close()
			subNames, err := k.ReadSubKeyNames(-1)
			if err != nil {
				log.Noticef("Error to open Subkey for %s : %s", key, err)
				continue
			}
			for _, each := range subNames {
				newKey := strings.Replace(key, "**", each, 1)
				if hkcu {
					//TODO fix if ** only get subname for current user
					ukeyCheck(newKey, ioc.Name, ioc.Value, ioc.Type, ioc.Description)
				}
				keyCheck(newKey, ioc.Name, ioc.Value, ioc.Type, ioc.Description, baseHandle)
			}
			continue
		}
		if hkcu {
			ukeyCheck(key, ioc.Name, ioc.Value, ioc.Type, ioc.Description)
		}
		keyCheck(key, ioc.Name, ioc.Value, ioc.Type, ioc.Description, baseHandle)
	}
	return nil
}
