// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type copyFile struct {
	TokenHash []byte   `json:"tokenHash"`
	Name      string   `json:"name"`
	Size      int64    `json:"size"`
	Sha256    string   `json:"sha256"`
	ModTsec   int64    `json:"modtsec"`
}

type fileCopyStatus struct {
	gotFileInfo   bool
	filename      string
	fileSize      int64
	fileHash      string
	currSize      int64
	modTime       time.Time
	buf           []byte
	f             *os.File
}

func runCopy(opt string) {
	path := strings.SplitN(opt, "cp/", 2)
	if len(path) != 2 {
		fmt.Printf("cp needs a cp/ and path input\n")
		return
	}
	file := path[1]
	info, err := os.Stat(file)
	if err != nil {
		fmt.Printf("os stat error %v\n", err)
		return
	}
	//fmt.Printf("file info %+v\n", info)
	cfile := copyFile{
		TokenHash: tokenHash16,
		Name:      info.Name(),
		Size:      info.Size(),
		ModTsec:   info.ModTime().Unix(),
		Sha256:    fmt.Sprintf("%x", getFileSha256(file)),
	}
	jbytes, err := json.Marshal(cfile)
	if err != nil {
		fmt.Printf("json marshal error %v\n", err)
		return
	}
	_ = websocketConn.WriteMessage(websocket.BinaryMessage, jbytes)

	// server side set
	isSvrCopy = true
	copyMsgChn = make(chan []byte)
	//websocketConn.SetReadDeadline(time.Now().Add(60 * time.Second))
	ahead := make(chan struct{})
	done := make(chan struct{})
	t := time.NewTimer(30 * time.Second)
	readerRunning := true

	go func() {
		for {
			select {
			case message := <-copyMsgChn:
				if !strings.Contains(string(message), startCopyMessage) {
					fmt.Printf("webc read message. %s\n", string(message))
					//websocketConn.SetReadDeadline(time.Time{})
					readerRunning = false
					if !isClosed(ahead) {
						close(ahead)
					}
					isSvrCopy = false
					return
				} else {
					//fmt.Printf("start file transfer\n")
					close(ahead)
				}

			case <-t.C:
				readerRunning = false
				if !isClosed(ahead) {
					close(ahead)
				}
				isSvrCopy = false
				return

			case <- done:
				t.Stop()
				isSvrCopy = false
				return
			}
		}
	}()

	<- ahead
	if !readerRunning {
		return
	}
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("os open error %v\n", err)
		return
	}
	defer f.Close()

	buffer := make([]byte, 8192)
	totalBytes := 0
	for {
		n, err := f.Read(buffer)
		if err != nil {
			fmt.Printf("file read error %v\n", err)
			return
		}
		_ = websocketConn.WriteMessage(websocket.BinaryMessage, buffer[:n])
		totalBytes += n
		if totalBytes >= int(cfile.Size) {
			break
		}
	}
	close(done)
}

// client side receive copied file
func getCopyFile(msg []byte, fstatus *fileCopyStatus, mtype int) {
	var info copyFile
	if !fstatus.gotFileInfo {
		err := json.Unmarshal(msg, &info)
		if err != nil {
			//sendCopyErr("json unmarshal info file", err)
			// print the device info first
			fmt.Printf("%s\n", []byte(msg))
			return
		}

		if !bytes.Equal(tokenHash16, info.TokenHash) {
			fmt.Printf("copy file token hash not match\n")
			return
		}

		fstatus.filename = info.Name
		fstatus.fileSize = info.Size
		fstatus.fileHash = info.Sha256
		fstatus.modTime = time.Unix(info.ModTsec, 0)
		fstatus.buf = make([]byte, info.Size)

		fmt.Printf("file: name %s, size %d\n", fstatus.filename, fstatus.fileSize)
		fstatus.gotFileInfo = true

		_, err = os.Stat(fileCopyDir)
		if err != nil {
			sendCopyErr("file stat ", err)
			return
		}
		fstatus.f, err = os.Create(fileCopyDir+fstatus.filename)
		if err != nil {
			sendCopyErr("file create", err)
			return
		}
		err = websocketConn.WriteMessage(websocket.TextMessage, []byte(startCopyMessage))
		if err != nil {
			sendCopyErr("write start copy failed", err)
		}
		return
	}
	if mtype == websocket.TextMessage {
		fmt.Printf("recv test msg, exit\n")
		isCopy = false
		return
	}
	n, err := fstatus.f.Write(msg)
	if err != nil {
		isCopy = false
		fmt.Printf("file write error: %v\n", err)
		return
	}
	fstatus.currSize += int64(n)
	if fstatus.currSize >= fstatus.fileSize {
		fstatus.f.Close()
		shaStr := fmt.Sprintf("%x", getFileSha256(fileCopyDir+fstatus.filename))
		if shaStr == fstatus.fileHash {
			fmt.Printf("\n done. file sha256 verified\n")
			err := os.Chtimes(fileCopyDir+fstatus.filename, fstatus.modTime, fstatus.modTime)
			if err != nil {
				fmt.Printf("modify file time: %v\n", err)
			}
		} else {
			fmt.Printf("\n file sha256 different. %s, should be %s\n", shaStr, fstatus.fileHash)
		}
		sendCopyErr("done", nil)
	}
}

func sendCopyErr(context string, err error) {
	if err != nil {
		fmt.Printf("%s error: %v\n", context, err)
	}
	_ = websocketConn.WriteMessage(websocket.TextMessage, []byte(context))
	isCopy = false
}
