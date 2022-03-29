// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	startCopyMessage  = "+++Start-Copy+++"
	fileCopyDir       = "/download/"
)

var (
	isCopy        bool           // client side
	isSvrCopy     bool           // server side
	copyMsgChn    chan []byte
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

	cfile := copyFile{
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

	// send file information to client side and wait for signal to start copy
	err = signAuthAndWriteWss(jbytes, false)
	if err != nil {
		fmt.Printf("sign and write error: %v\n", err)
		return
	}

	// server side set
	isSvrCopy = true
	copyMsgChn = make(chan []byte)
	ahead := make(chan struct{})
	done := make(chan struct{})
	t := time.NewTimer(30 * time.Second)
	readerRunning := true

	go func() {
		for {
			select {
			case message := <-copyMsgChn:
				if !strings.Contains(string(message), startCopyMessage) {
					log.Noticef("webc read message. %s", string(message))
					readerRunning = false
					if !isClosed(ahead) {
						close(ahead)
					}
					isSvrCopy = false
					return
				} else {
					// start copy file transfer
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

		err = signAuthAndWriteWss(buffer[:n], false)
		if err != nil {
			fmt.Printf("file write to wss error %v\n", err)
			return
		}
		totalBytes += n
		if totalBytes >= int(cfile.Size) {
			break
		}
	}
	close(done)
}

// client side receive copied file
func recvCopyFile(msg []byte, fstatus *fileCopyStatus, mtype int) {
	var info copyFile
	if !fstatus.gotFileInfo {
		err := json.Unmarshal(msg, &info)
		if err != nil {
			fmt.Printf("%s\n", []byte(msg))
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
			sendCopyDone("file stat ", err)
			return
		}
		fstatus.f, err = os.Create(fileCopyDir+fstatus.filename)
		if err != nil {
			sendCopyDone("file create", err)
			return
		}

		err = signAuthAndWriteWss([]byte(startCopyMessage), false)
		if err != nil {
			sendCopyDone("write start copy failed", err)
		}
		return
	}
	if mtype == websocket.TextMessage {
		fmt.Printf("recv text msg, exit\n")
		isCopy = false
		fstatus.f.Close()
		return
	}

	n, err := fstatus.f.Write(msg)
	if err != nil {
		isCopy = false
		fstatus.f.Close()
		fmt.Printf("file write error: %v\n", err)
		return
	}
	fstatus.currSize += int64(n)
	if fstatus.currSize >= fstatus.fileSize {
		fstatus.f.Close()
		shaStr := fmt.Sprintf("%x", getFileSha256(fileCopyDir+fstatus.filename))
		if shaStr == fstatus.fileHash {
			err := os.Chtimes(fileCopyDir+fstatus.filename, fstatus.modTime, fstatus.modTime)
			if err != nil {
				fmt.Printf("modify file time: %v\n", err)
			}
			untarLogfile(fstatus.filename)
		} else {
			fmt.Printf("\n file sha256 different. %s, should be %s\n", shaStr, fstatus.fileHash)
		}
		sendCopyDone("done", nil)
	}
}

func sendCopyDone(context string, err error) {
	if err != nil {
		fmt.Printf("%s error: %v\n", context, err)
	}
	err = signAuthAndWriteWss([]byte(context), true)
	if err != nil {
		fmt.Printf("sign and write error: %v\n", err)
	}
	isCopy = false
}

func untarLogfile(downloadedFile string) {
	if !strings.HasPrefix(downloadedFile, "logfiles-") || !strings.HasSuffix(downloadedFile, ".tar") {
		fmt.Printf("\n file saved at %s\n\n", fileCopyDir + downloadedFile)
		return
	}

	cmdStr := "cd " + fileCopyDir + "; tar xvf " + downloadedFile
	untarCmd := exec.Command("sh", "-c", cmdStr)
	err := untarCmd.Run()
	if err != nil {
		fmt.Printf("untar error: %v\n", err)
	} else {
		_ = os.Remove(fileCopyDir+downloadedFile)
	}

	fileStr := strings.SplitN(downloadedFile, ".tar", 2)
	if len(fileStr) != 2 {
		return
	}
	logSaveDir := fileCopyDir + fileStr[0]
	fmt.Printf("\n log files saved at %s\n\n", logSaveDir)
	cmdStr = "ls -lt " + logSaveDir
	retBytes, _ := exec.Command("sh", "-c", cmdStr).Output()
	fmt.Printf("%s\n", retBytes)
}

func runCopyLogfiles(logfiles []logfiletime, time1 int64) {

	timeStr := getFileTimeStr(time.Unix(time1, 0))
	destinationfile := "/tmp/logfiles-" + timeStr + ".tar"

	// no need for compression since the logfiles are already in
	// gzip compressed format
	tarfile, err := os.Create(destinationfile)
	if err != nil {
		log.Errorf("runCopyLogfiles create error %v", err)
		return
	}
	defer tarfile.Close()

	var fileWriter io.WriteCloser = tarfile

	tarfileWriter := tar.NewWriter(fileWriter)
	defer tarfileWriter.Close()

	for _, logfile := range logfiles {
		fileInfo, err := os.Stat(logfile.filepath)
		if err != nil {
			log.Errorf("runCopyLogfiles can not stat: %v", err)
			continue
		}
		file, err := os.Open(logfile.filepath)
		if err != nil {
			log.Errorf("runCopyLogfiles file open error: %v", err)
			continue
		}
		defer file.Close()

		// prepare the tar header
		header := new(tar.Header)
		header.Name = "logfiles-" + timeStr + "/" + filepath.Base(file.Name())
		header.Size = fileInfo.Size()
		header.Mode = int64(fileInfo.Mode())
		header.ModTime = fileInfo.ModTime()

		err = tarfileWriter.WriteHeader(header)
		if err != nil {
			log.Errorf("runCopyLogfiles write header error: %v", err)
			continue
		}

		_, err = io.Copy(tarfileWriter, file)
		if err != nil {
			log.Errorf("runCopyLogfiles copy file error: %v", err)
			continue
		}
		file.Close()
	}
	tarfileWriter.Close()
	tarfile.Close()

	// use the normal 'cp' utility to transfer the tar file over
	runCopy("cp/" + destinationfile)
	_ = os.Remove(destinationfile)
}