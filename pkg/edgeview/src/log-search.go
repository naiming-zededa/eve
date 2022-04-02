// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/api/go/logs"
)


type logfiletime struct {
	filepath    string
	filesec     int64
}

// LogContent - log content struct
type LogContent struct {
	File     string    `json:"file,omitempty"`
	Func     string    `json:"func,omitempty"`
	IfName   string    `ifname:"func,omitempty"`
	Level    string    `json:"level,omitempty"`
	Msg      string    `json:"msg,omitempty"`
	Objtype  string    `json:"obj_type,omitempty"`
	PID      int       `json:"pid,omitempty"`
	Source   string    `json:"source,omitempty"`
	Time     string    `json:"time,omitempty"`
}

func runLogSearch(cmds cmdOpt) {
	pattern := cmds.Logopt
	timeline := cmds.Timerange
	extralog := cmds.Extraline
	var copylogfiles bool
	log.Tracef("log pattern %s, time %s, json %v, extraline %d, type %s",
		pattern, timeline, cmds.IsJSON, extralog, querytype)

	if !strings.Contains(timeline, "-") {
		fmt.Printf("log time needs to have dash between start and end\n")
		return
	}

	now := time.Now().Unix()
	// t1 >= t2 int64
	t1, t2 := getTimeSec(timeline, now)
	if pattern == cpLogFileString {
		if t1 - t2 > 1800 {
			fmt.Printf("copy-logfiles can only in the range of 30 minutes\n")
			return
		}
		copylogfiles = true
	}

	gfiles := walkLogDirs(t1, t2, now)
	if copylogfiles {
		runCopyLogfiles(gfiles, t1)
		return
	}

	op := " | grep -E "
	if extralog > 0 {
		op = " | grep -A " + strconv.Itoa(extralog) + " -B " + strconv.Itoa(extralog) + " -E "
	}
	var printIdx int
	for _, gf := range gfiles {
		cmd := "zcat " + gf.filepath + op + pattern
		olines, err := runCmd(cmd, true, false)
		if err == nil && len(olines) > 0 {
			bout := fmt.Sprintf("\n %s, -- %v --\n", gf.filepath, time.Unix(gf.filesec, 0).Format(time.RFC3339))
			printColor(bout, colorRED)

			colorMatch(olines, pattern, &printIdx, cmds.IsJSON)
		}
	}

	if now - t1 < 10 { // search for collect directory for uncompressed files
		if querytype != "app" {
			searchLiveLogs(pattern, now, "dev", &printIdx, cmds.IsJSON)
		}
		if querytype != "dev" {
			searchLiveLogs(pattern, now, "app", &printIdx, cmds.IsJSON)
		}
	}
	fmt.Println()
}

func walkLogDirs(t1, t2, now int64) []logfiletime {
	var getfiles []logfiletime
	toMin := int((now - t2) / 60) + 10 // give 10 min more
	fromMin := int((now - t1) / 60)
	if fromMin > 10 {
		fromMin -= 10
	}

	newlogs, err := runCmd("ls /persist/newlog", false, false)
	if err != nil {
		fmt.Printf("ls /persist/newlog error %v\n", err)
		return getfiles
	}
	logdir := strings.Split(newlogs, "\n")

	gzfiles := make(map[string][]string)
	for _, dir := range logdirectory {
		var found bool
		for _, d := range logdir {
			if strings.Contains(dir, d) {
				found = true
				break
			}
		}
		if found {
			cmd := "cd " + dir + " && find . -mmin -" + strconv.Itoa(toMin) + " -mmin +" + strconv.Itoa(fromMin)
			lineStr, err := runCmd(cmd, false, false)
			if err == nil {
				files := strings.Split(lineStr, "\n")
				gzfiles[dir] = files
			}
		}
	}

	for k, g := range gzfiles {
		//fmt.Printf("- %s, file: %s\n", k, g)
		for _, file := range g {
			if !strings.Contains(file, "dev") && !strings.Contains(file, "app") {
				continue
			}
			if querytype == "app" && !strings.Contains(file, "app") {
				continue
			}
			if querytype == "dev" && !strings.Contains(file, "dev") {
				continue
			}
			ftime := getFileTime(file)
			if ftime == 0 {
				continue
			}
			if ftime >= t2 && ftime <= t1 {
				file1 := strings.TrimPrefix(file, "./")
				gfile := logfiletime{
					filepath: k + file1,
					filesec: ftime,
				}
				getfiles = append(getfiles, gfile)
			}
		}
	}

	sort.Slice(getfiles, func(i1, i2 int) bool {
		return getfiles[i1].filesec < getfiles[i2].filesec
	})

	return getfiles
}

func searchLiveLogs(pattern string, now int64, typeStr string, idx *int, logjson bool) {
	retStr, err := runCmd("ls /persist/newlog/collect/", false, false)
	if err != nil {
		return
	}
	lines := strings.Split(retStr, "\n")
	if len(lines) == 0 {
		return
	}
	for _, l := range lines[:len(lines)-1] {
		if !strings.HasPrefix(l, typeStr) {
			continue
		}
		file := "/persist/newlog/collect/" + l
		searchCurrentLogs(pattern, file, typeStr, now, idx, logjson)
	}
}

func searchCurrentLogs(pattern, path, typeStr string, now int64, idx *int, logjson bool) {
	retStr, err := runCmd("grep " + pattern + " " + path, false, false)
	if err == nil && len(retStr) > 0 {
		bout := fmt.Sprintf("\n current " + typeStr + " log, -- %v --\n", time.Unix(now, 0).Format(time.RFC3339))
		printColor(bout, colorRED)

		colorMatch(retStr, pattern, idx, logjson)
	}
}

func colorMatch(olines, pattern string, idx *int, logjson bool) {
	lines := strings.Split(olines, "\n")
	if strings.Contains(pattern, "|") {
		pat := strings.Split(pattern, "|")
		pattern = strings.TrimSuffix(pat[0], " ")
	}
	for i, l := range lines[:len(lines)-1] {
		if logjson {
			prettyJSON, err := formatJSON([]byte(l))
			if err == nil {
				buff := strings.ReplaceAll(string(prettyJSON), pattern, "\033[0;93m"+pattern+"\033[0m")
				fmt.Printf(" (%d) %s\n", i+1, buff)
			}
		} else {
			var entry logs.LogEntry
			var content LogContent
			var bufStr string
			_ = json.Unmarshal([]byte(l), &entry)
			err := json.Unmarshal([]byte(entry.Content), &content)
			*idx++
			if err != nil {
				var tlog string
				if entry.Timestamp != nil {
					tlog = time.Unix(entry.Timestamp.Seconds, 0).Format(time.RFC3339)
				}
				bufStr = fmt.Sprintf(" -(%d) %s, %s, %s, %v(%d)", *idx, strings.TrimSuffix(entry.Content, "\n"), entry.Severity, entry.Source,
					tlog, entry.Msgid)
			} else {
				bufStr = fmt.Sprintf(" -(%d) %s, %s, %s, %s, %s, %s, %s(%d)",
					*idx, content.Msg, entry.Severity, entry.Filename, entry.Function, content.Objtype,
					content.Source, content.Time, entry.Msgid)
			}
			buff := strings.ReplaceAll(bufStr, pattern, "\033[0;93m"+pattern+"\033[0m")
			fmt.Printf("%s\n", buff)
		}
		if !directQuery && i%20 == 0 {
			closePipe(true)
		}
	}
}

func getTimeSec(timeline string, now int64) (int64, int64) {
	var ti1, ti2 int64
	if strings.Contains(timeline, "Z-") {
		times := strings.Split(timeline, "Z-")

		t1, _ := time.Parse(time.RFC3339, times[0] + "Z")
		t2, _ := time.Parse(time.RFC3339, times[1])
		ti1 = t1.Unix()
		ti2 = t2.Unix()
		if ti1 > now {
			ti1 = now
		}
		if ti2 > now {
			ti2 = now
		}
	} else {
		times := strings.Split(timeline, "-")
		f1, err1 := strconv.ParseFloat(times[0], 16)
		f2, err2 := strconv.ParseFloat(times[1], 16)
		if err1 != nil || err2 != nil {
			fmt.Printf("float error %v, %v\n", err1, err2)
		}

		ti1 = now - int64(f1 * 3600)
		ti2 = now - int64(f2 * 3600)
	}
	if ti1 >= ti2 {
		return ti1, ti2
	} else {
		return ti2, ti1
	}
}
