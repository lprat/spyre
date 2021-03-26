// +build linux amd64

package command

import (
	"fmt"
	"encoding/base64"
	"os/exec"
	"bytes"
	"github.com/spyre-project/spyre/config"
	"github.com/spyre-project/spyre/log"
	"github.com/spyre-project/spyre/report"
	"github.com/spyre-project/spyre/scanner"
)

func init() { scanner.RegisterSystemScanner(&systemScanner{}) }

type systemScanner struct {
	iocs []commandIOC
}

type commandIOC struct {
	Command         string `json:"command"`
  Commandargs         []string `json:"commandargs"`
  Description     string   `json:"description"`
}

type iocFile struct {
	Keys []commandIOC `json:"command"`
}

func (s *systemScanner) Name() string { return "Command" }

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
    cmd := exec.Command(ioc.Command, ioc.Commandargs...)
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr
    err := cmd.Run()
    if err != nil {
        log.Errorf("Error to run command %s -- error: %s",ioc.Description, err)
        continue
    }
    outStr, errStr := base64.StdEncoding.EncodeToString(stdout.Bytes()), base64.StdEncoding.EncodeToString(stderr.Bytes())
    message := fmt.Sprintf("Command runned: %s",ioc.Description)
    report.AddProcInfo("extracted_info", message,
      "rule", ioc.Description, "extracted_stdout", outStr, "extracted_stderr", errStr,
    )
	}
	return nil
}
