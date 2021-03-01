package report

import (
	"github.com/spyre-project/spyre/log"

	"github.com/spf13/afero"
)

var targets []target

type ProcInfo struct {
  name  string
	value interface{}
}

func Init() error {
	for _, spec := range config.ReportTargets {
		tgt, err := mkTarget(spec)
		if err != nil {
			return err
		}
		targets = append(targets, tgt)
	}
	log.Noticef("Writing report to %s", config.ReportTargets)
	return nil
}

// AddStringf adds a single message with fmt.Printf-style parameters.
func AddStringf(f string, v ...interface{}) {
	for _, t := range targets {
		t.formatMessage(t.writer, f, v...)
	}
}

func AddFileInfo(file afero.File, description, message string, extra ...string) {
	for _, t := range targets {
		t.formatFileEntry(t.writer, file, description, message, extra...)
	}
}

func AddEvtxInfo(evt string, description, message string, extra ...string) {
	for _, t := range targets {
		t.formatEvtxEntry(t.writer, evt, description, message, extra...)
	}
}

func AddNetstatInfo(description, message string, extra ...string) {
	for _, t := range targets {
		t.formatNetstatEntry(t.writer, description, message, extra...)
	}
}

func AddAutorunInfo(description, message string, extra ...string) {
	for _, t := range targets {
		t.formatAutorunEntry(t.writer, description, message, extra...)
	}
}

func AddRegistryInfo(description, message string, extra ...string) {
	for _, t := range targets {
		t.formatRegistryEntry(t.writer, description, message, extra...)
	}
}

func AddProcInfo(proc []ProcInfo, description, message string, extra ...string) {
	for _, t := range targets {
		t.formatProcEntry(t.writer, proc, description, message, extra...)
	}
}

// Close shuts down all reporting targets
func Close() {
	for _, t := range targets {
		t.finish(t.writer)
		t.writer.Close()
	}
}
