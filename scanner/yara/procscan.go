package yara

import (
	"strings"
  "strconv"
	yr "github.com/lprat/go-yara/v4"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/spyre-project/spyre/config"
	"github.com/spyre-project/spyre/report"
	"github.com/spyre-project/spyre/scanner"

	"time"
)

func init() { scanner.RegisterProcScanner(&procScanner{}) }

type procScanner struct{ rules *yr.Rules }

func (s *procScanner) Name() string { return "YARA-proc" }

func (s *procScanner) Init() error {
	var err error
	s.rules, err = compile(procscan, config.YaraProcRules)
	return err
}

func (s *procScanner) ScanProc(pid int32) error {
	var matches yr.MatchRules
  handle, err := process.NewProcess(pid)
	if err {
	    return err
	}
	exe, err := handle.Name()
  if err {
    exe = ''
  }
	if !(stringInSlice(exe, config.ProcIgnoreList)) {
		return "Skipping process (found on ignore list) %s[%d].", exe, pid
	}
	ppid, err := handle.Ppid()
  if err {
    ppid = ''
  } else {
		ppid = strconv.FormatInt(int64(ppid), 10)
	}
	phandle, err := handle.Parent()
	pcmdline, err := phandle.Cmdline()
  if err {
    pcmdline = ''
  }
	pexe, err := phandle.Name()
  if err {
    pexe = ''
  }
	ppathexe, err := phandle.Exe()
  if err {
    ppathexe = ''
  }
	pusername, err := phandle.Username()
  if err {
    pusername = ''
  }
	cmdline, err := handle.Cmdline()
  if err {
    cmdline = ''
  }
	pathexe, err := handle.Exe()
  if err {
    pathexe = ''
  }
	username, err := handle.Username()
  if err {
    username = ''
  }
	crt_time, err := handle.CreateTime()
	if err {
    crt_time = 0
  }
	childrens, err := handle.Children()
	var child_cmdline []strings
	var child_pathexe []strings
	var child_username []strings
	var child_exe []strings
  if err == nil {
	  for _, handlechild := range childrens {
			cmdline, err := handlechild.Cmdline()
			if err == nil {
				if stringInSlice(cmdline, child_cmdline) {
		      child_cmdline = append(child_cmdline, cmdline)
			  }
		  }
			exe, err := handlechild.Name()
		  if err == nil {
				if stringInSlice(exe, child_exe) {
		      child_exe = append(child_exe, exe)
			  }
		  }
			pathexe, err := handlechild.Exe()
			if err == nil {
				if stringInSlice(pathexe, child_pathexe) {
		      child_pathexe = append(child_pathexe, pathexe)
			  }
		  }
			username, err := handlechild.Username()
			if err == nil {
				if stringInSlice(username, child_username) {
		      child_username = append(child_username, username)
			  }
		  }
	  }
  }
	for _, v := range []struct {
		name  string
		value interface{}
	}{
		{"pid", strconv.FormatInt(int64(pid), 10)},
		{"pathexe", pathexe},
		{"cmdline", cmdline},
		{"executable", exe},
		{"username", username},
		{"ppid", ppid},
		{"ppathexe", ppathexe},
		{"pcmdline", pcmdline},
		{"pexecutable", pexe},
		{"pusername", pusername},
		{"ccmdline", strings.Join(child_cmdline, "|")},
		{"cpathexe", strings.Join(child_pathexe, "|")},
		{"cusername", strings.Join(child_username, "|")},
		{"cexecutable", strings.Join(child_exe, "|")},
	} {
		if err := s.rules.DefineVariable(v.name, v.value); err != nil {
			return err
		}
	}
	err := s.rules.ScanProc(pid, yr.ScanFlagsProcessMemory, 4*time.Minute, &matches)
	for _, m := range matches {
		var matchx []string
		for _, ms := range m.Strings {
			if stringInSlice(ms.Name+"-->"+string(ms.Data), matchx) {
				matchx = append(matchx, ms.Name+"-->"+string(ms.Data))
			}
		}
		matched := strings.Join(matchx[:], " | ")
		message := m.Rule+" (yara) matched on process: "+exe+"["+pathexe+"]("+username+")"
		if strings.HasPrefix("m.Rule", "kill_") {
			err = handle.Kill()
			if err == nil {
			  message = "Killed process by "+m.Rule+" (yara) matched on process: "+exe+"["+pathexe+"]("+username+")"
			} else {
				message = "Error to kill process by "+m.Rule+" (yara) matched on process: "+exe+"["+pathexe+"]("+username+")"
			}
		}
		infoproc := []struct {
		  name  string
		  value interface{}
	  } {
			{"PID", strconv.FormatInt(int64(pid), 10)},
			{"pathexe", pathexe},
			{"cmdline", cmdline},
			{"Process", exe},
			{"username", username},
			{"real_date", crt_time},
			{"Parent_pathexe", ppathexe},
			{"Parent_cmdline", pcmdline},
			{"Parent_Process", pexe},
			{"Parent_username", pusername},
			{"Child_cmdline", child_cmdline},
			{"Child_pathexe", child_pathexe},
			{"Child_username", child_username},
			{"Child_Process", child_exe},
	  }
		report.AddProcInfo(infoproc, "yara_on_pid", message, "rule", m.Rule, "string_match", string(matched))
	}
	return err
}
