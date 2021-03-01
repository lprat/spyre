package report

import (
	"github.com/spyre-project/spyre"

	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/spf13/afero"
)

type formatterPlain struct{}

type ProcInfo struct {
  name  string
	value interface{}
}

func (f *formatterPlain) emitTimeStamp(w io.Writer) {
	w.Write([]byte(time.Now().Format(time.RFC3339) + " " + spyre.Hostname + " "))
}

func fmtExtra(extra []string) string {
	var ex string
	if len(extra) > 0 {
		ex = ";"
		if len(extra)%2 != 0 {
			extra = append(extra, "")
		}
		for len(extra) > 0 {
			ex += " " + extra[0] + "=" + extra[1]
			if len(extra) > 2 {
				ex += ", "
			}
			extra = extra[2:]
		}
	}
	return ex
}

func (f *formatterPlain) formatFileEntry(w io.Writer, file afero.File, description, message string, extra ...string) {
	//f.emitTimeStamp(w)
	fmt.Fprintf(w, "%s %s %s: %s: %s%s\n", time.Now().Format(time.RFC3339), spyre.Hostname, description, file.Name(), message, fmtExtra(extra))
	//w.Write([]byte{'\n'})
}

func (f *formatterPlain) formatNetstatEntry(w io.Writer, description, message string, extra ...string) {
	// send directly all for avoid anomalie formated line
	//f.emitTimeStamp(w)
	fmt.Fprintf(w, "%s %s %s: %s%s\n", time.Now().Format(time.RFC3339), spyre.Hostname, description, message, fmtExtra(extra))
	//w.Write([]byte{'\n'})
}

func (f *formatterPlain) formatRegistryEntry(w io.Writer, description, message string, extra ...string) {
	// send directly all for avoid anomalie formated line
	//f.emitTimeStamp(w)
	fmt.Fprintf(w, "%s %s %s: %s%s\n", time.Now().Format(time.RFC3339), spyre.Hostname, description, message, fmtExtra(extra))
	//w.Write([]byte{'\n'})
}

func (f *formatterPlain) formatAutorunEntry(w io.Writer, description, message string, extra ...string) {
	// send directly all for avoid anomalie formated line
	//f.emitTimeStamp(w)
	fmt.Fprintf(w, "%s %s %s: %s%s\n", time.Now().Format(time.RFC3339), spyre.Hostname, description, message, fmtExtra(extra))
	//w.Write([]byte{'\n'})
}

func (f *formatterPlain) formatEvtxEntry(w io.Writer, evt string, description, message string, extra ...string) {
	// send directly all for avoid anomalie formated line
	//f.emitTimeStamp(w)
	fmt.Fprintf(w, "%s %s %s: ---%s--- : %s%s\n", time.Now().Format(time.RFC3339), spyre.Hostname, description, evt, message, fmtExtra(extra))
	//w.Write([]byte{'\n'})
}

func (f *formatterPlain) formatProcEntry(w io.Writer, p []ProcInfo, description, message string, extra ...string) {
	//f.emitTimeStamp(w)
	fmt.Fprintf(w, "%s %s %s: %v: %s%s\n", time.Now().Format(time.RFC3339), spyre.Hostname, description, p, message, fmtExtra(extra))
	//w.Write([]byte{'\n'})
}

func (f *formatterPlain) formatMessage(w io.Writer, format string, a ...interface{}) {
	f.emitTimeStamp(w)
	if format[len(format)-1] != '\n' {
		format += "\n"
	}
	fmt.Fprintf(w, format, a...)
}

func (formatterPlain) finish(w io.Writer) {}

type formatterTSJSON struct {
	initialized bool
}

func (f *formatterTSJSON) emitRecord(w io.Writer, kv ...string) {
	if f.initialized {
		w.Write([]byte(",\n"))
	} else {
		w.Write([]byte("[\n"))
		f.initialized = true
	}
	now := time.Now()
	r := make(map[string]string)
	r["timestamp"] = strconv.Itoa(int(now.UnixNano() / 1000))
	r["datetime"] = now.Format(time.RFC3339)
	r["hostname"] = spyre.Hostname
	for it := kv; len(it) >= 2; it = it[2:] {
		r[it[0]] = it[1]
	}
	buf, _ := json.Marshal(r)
	w.Write(buf)
}

func (f *formatterTSJSON) formatFileEntry(w io.Writer, file afero.File, description, message string, extra ...string) {
	fileinfo := []string{"filename", file.Name()}
	if fi, err := file.Stat(); err == nil {
		fileinfo = append(fileinfo, "file_size", strconv.Itoa(int(fi.Size())))
	}
	extra = append([]string{"timestamp_desc", description, "message", message}, extra...)
	extra = append(fileinfo, extra...)
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSON) formatEvtxEntry(w io.Writer, evt string, description, message string, extra ...string) {
	extra = append([]string{"timestamp_desc", description, "message", message}, extra...)
	extra = append([]string{"evtx", evt}, extra...)
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSON) formatNetstatEntry(w io.Writer, description, message string, extra ...string) {
	extra = append([]string{"timestamp_desc", description, "message", message}, extra...)
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSON) formatAutorunEntry(w io.Writer, description, message string, extra ...string) {
	extra = append([]string{"timestamp_desc", description, "message", message}, extra...)
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSON) formatRegistryEntry(w io.Writer, description, message string, extra ...string) {
	extra = append([]string{"timestamp_desc", description, "message", message}, extra...)
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSON) formatProcEntry(w io.Writer, p []ProcInfo, description, message string, extra ...string) {
	extra = append([]string{"timestamp_desc", description, "message", message}, extra...)
	for _, x := range p {
	   fmt.Println(x.name)
		 extra = append(extra, x.name, x.value)
	}
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSON) formatMessage(w io.Writer, format string, a ...interface{}) {
	extra := []string{"timestamp_desc", "msg", "message", fmt.Sprintf(format, a...)}
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSON) finish(w io.Writer) {
	if !f.initialized {
		w.Write([]byte("["))
	}
	w.Write([]byte("\n]\n"))
}

type formatterTSJSONLines struct{}

func (f *formatterTSJSONLines) emitRecord(w io.Writer, kv ...string) {
	now := time.Now()
	r := make(map[string]string)
	r["timestamp"] = strconv.Itoa(int(now.UnixNano() / 1000))
	r["datetime"] = now.Format(time.RFC3339)
	//keep plaso name field
	r["computer_name"] = spyre.Hostname
	r["file_generator"] = "Spyre"
	for it := kv; len(it) >= 2; it = it[2:] {
		r[it[0]] = it[1]
	}
	json.NewEncoder(w).Encode(r)
}

func (f *formatterTSJSONLines) formatFileEntry(w io.Writer, file afero.File, description, message string, extra ...string) {
	fileinfo := []string{"filename", file.Name()}
	if fi, err := file.Stat(); err == nil {
		fileinfo = append(fileinfo, "file_size", strconv.Itoa(int(fi.Size())))
	}
	extra = append([]string{"timestamp_desc", description, "message", message}, extra...)
	extra = append(fileinfo, extra...)
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSONLines) formatEvtxEntry(w io.Writer, evt string, description, message string, extra ...string) {
	extra = append([]string{"timestamp_desc", description, "message", message}, extra...)
	extra = append([]string{"evtx", evt}, extra...)
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSONLines) formatNetstatEntry(w io.Writer, description, message string, extra ...string) {
	extra = append([]string{"timestamp_desc", description, "message", message}, extra...)
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSONLines) formatAutorunEntry(w io.Writer, description, message string, extra ...string) {
	extra = append([]string{"timestamp_desc", description, "message", message}, extra...)
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSONLines) formatRegistryEntry(w io.Writer, description, message string, extra ...string) {
	extra = append([]string{"timestamp_desc", description, "message", message}, extra...)
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSONLines) formatProcEntry(w io.Writer, p []ProcInfo, description, message string, extra ...string) {
	extra = append([]string{"timestamp_desc", description, "message", message}, extra...)
	for _, x := range p {
	   fmt.Println(x.name)
		 extra = append(extra, x.name, x.value)
	}
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSONLines) formatMessage(w io.Writer, format string, a ...interface{}) {
	extra := []string{"timestamp_desc", "msg", "message", fmt.Sprintf(format, a...)}
	f.emitRecord(w, extra...)
}

func (f *formatterTSJSONLines) finish(w io.Writer) {}
