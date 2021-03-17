// +build linux darwin freebsd netbsd openbsd solaris aix

package config

var procscan bool
var defaultPaths = []string{"/"}
var defaultEvtxPaths = []string{"/var/log/"}

func getdrive() []string {
	return defaultPaths
}
