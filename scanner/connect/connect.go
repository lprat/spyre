package connect

import (
	"fmt"
  "net"
  "strings"
  "time"
	"github.com/spyre-project/spyre/config"
	"github.com/spyre-project/spyre/log"
	"github.com/spyre-project/spyre/report"
	"github.com/spyre-project/spyre/scanner"
)

func init() { scanner.RegisterSystemScanner(&systemScanner{}) }

type systemScanner struct {
	iocs []connectIOC
}

type connectIOC struct {
	Ip         string `json:"ip"`
  Port         string `json:"port"`
  Protocol         string `json:"protocol"`
  // tcp or udp
  Timeout         string `json:"timeout"`
  //ex: 2s
  Send         string `json:"send"`
  Description     string   `json:"description"`
}

type iocFile struct {
	Keys []connectIOC `json:"connect"`
}

func (s *systemScanner) Name() string { return "Connect" }

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

func (s *systemScanner) Scan() error {
	for _, ioc := range s.iocs {
    state, receive := ScanPort(ioc.Ip, ioc.Port, ioc.Protocol, ioc.Send, ioc.Timeout)
    if state == 1 {
      message := fmt.Sprintf("Connected to: %s:%s [%s] - Open",ioc.Ip,ioc.Port,ioc.Protocol)
      report.AddProcInfo("connect", message,
        "rule", ioc.Description, "port", ioc.Port, "ip", ioc.Ip, "protocol", ioc.Protocol,
        "state", "open", "receive", receive,
      )
    } else if state == 0 {
      message := fmt.Sprintf("Connected to: %s:%s [%s] - Close",ioc.Ip,ioc.Port,ioc.Protocol)
      report.AddProcInfo("connect", message,
        "rule", ioc.Description, "port", ioc.Port, "ip", ioc.Ip, "protocol", ioc.Protocol,
        "state", "close",
      )
    } else {
      message := fmt.Sprintf("Connected to: %s:%s [%s] - Error",ioc.Ip,ioc.Port,ioc.Protocol)
      report.AddProcInfo("connect", message,
        "rule", ioc.Description, "port", ioc.Port, "ip", ioc.Ip, "protocol", ioc.Protocol,
        "state", "error",
      )
    }
	}
	return nil
}

func ScanPort(ip string, port string, protocol string, send string, stimeout string) (state int, receive string) {
    target := fmt.Sprintf("%s:%s", ip, port)
    timeout, err := getTimeout(stimeout)
    if err != nil {
			timeout = time.Second * 2
		}
    conn, err := net.DialTimeout(protocol, target, timeout)

    if err != nil {
        if strings.Contains(err.Error(), "too many open files") {
            return 2, ""
        } else {
            return 0, ""
        }
    }
    fmt.Fprintf(conn, send)
		conn.SetReadDeadline(time.Now().Add(10*time.Millisecond))

		buff := make([]byte, 1024)
		n, _ := conn.Read(buff)
    conn.Close()
    return 1, string(buff[:n])
}

func getTimeout(timeOutParameter string) (timeOut time.Duration, err error) {

	switch {
	case strings.HasSuffix(timeOutParameter, "ms"):
		timeOut, err = time.ParseDuration(timeOutParameter)
	case strings.HasSuffix(timeOutParameter, "s"):
		timeOut, err = time.ParseDuration(timeOutParameter)
	case strings.HasSuffix(timeOutParameter, "m"):
		timeOut, err = time.ParseDuration(timeOutParameter)
	default:
		timeOut, err = time.ParseDuration(timeOutParameter + "ms")
	}

	return timeOut, err
}
