// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

func runPubsub(pubStr string) {
	opts, err := checkOpts(pubStr, pubsubopts)
	if err != nil {
		fmt.Println("runPubsub:", err)
	}

	startdir := []string{"/run/", "/persist/status/", "/persist/pubsub-large/"}
	for _, p := range opts {
		printTitle("\n === Pub/Sub: <"+p+"> ===\n\n", colorPURPLE, false)

		var pubsubdir, subdir string
		if strings.Contains(p, "/") {
			items := strings.Split(p, "/")
			pubsubdir = items[0]
			subdir = items[1]
		} else {
			pubsubdir = p
			subdir = ""
		}

		for _, sdir := range startdir {
			if sdir == "/persist/status/" {
				opts1, _ := checkOpts(pubStr, pubsubpersist)
				if len(opts1) == 0 {
					break
				}
			} else if sdir == "/persist/pubsub-large/" {
				opts1, _ := checkOpts(pubStr, pubsublarge)
				if len(opts1) == 0 {
					break
				}
			}

			printColor("\n pubsub in: "+sdir, colorBLUE)

			if subdir != "" {
				retData, err := runCmd("cd "+sdir+pubsubdir+" && ls | grep -i "+subdir, false, false)
				if err != nil {
					continue
				}
				lines := strings.Split(retData, "\n")
				n := len(lines)
				for _, sub := range lines[:n-1] {
					if strings.Contains(sub, ".sock") || strings.Contains(sub, ".conf") || sub == "" {
						continue
					}
					subdir = sub
					pubsubSvs(sdir, pubsubdir, subdir)
				}
			} else {
				pubsubSvs(sdir, pubsubdir, subdir)
			}
			closePipe(true)
		}
	}
}

func pubsubSvs(startDir, pubsubDir, subDir string) {
	newdir := startDir + pubsubDir
	if subDir != "" {
		newdir = newdir + "/" + subDir
	}

	cmd := "cd " + newdir + " && find . -name '*.json' -print"
	retData, err := runCmd(cmd, false, false)
	if err != nil {
		fmt.Printf("pubsubSvs: error %v\n", err)
		return
	}

	files := strings.Split(retData, "\n")
	n := len(files)
	printpath := ""
	for _, f := range files[:n-1] {
		dir1 := strings.Split(f, "./")
		paths := strings.Split(dir1[1], "/")
		path := ""
		for _, p := range paths[:len(paths)-1] {
			path = path + "/" + p
		}
		if printpath != newdir+path {
			printColor("  "+newdir+path, colorGREEN)
			printpath = newdir + path
		}
		dirfile := newdir + "/" + dir1[1]
		fmt.Printf("   service: %s\n", paths[len(paths)-1])
		retData, err := runCmd("cat "+dirfile, false, false)
		if err != nil {
			continue
		}
		prettyJSON, err := formatJSON([]byte(retData))
		if err != nil {
			fmt.Printf("JsonFormet error %v\n", err)
		}

		fmt.Println(string(prettyJSON))
	}
}

func formatJSON(data []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, data, "", "    ")
	if err == nil {
		return out.Bytes(), err
	}
	return data, nil
}
