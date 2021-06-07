// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package pubsub

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

const (
	// maxLargeLen is the largest single file we support
	maxLargeLen = 1024 * 1024
	// tagLarge is the prefix in the json tag which directs us to use files
	tagLarge = "pubsub-large-"
	// tagFile is the internal prefix we use for the filename
	tagFile = "pubsub-file-"
)

// The generic type for a json decode
type jsonTree map[string]interface{}

// removeLarge removes all json with the tagLarge prefix
func removeLarge(log *base.LogObject, b []byte, rootDir string) ([]byte, error) {
	return writeLargeImpl(log, b, "", rootDir)
}

// writeAndRemoveLarge looks for the tagLarge prefix, saves the content of those
// fields to uniquely-named files under dirname, and inserts tagFile prefixed
// fields in the json to specify the fileaname
func writeAndRemoveLarge(log *base.LogObject, b []byte, dirname string) ([]byte, error) {
	return writeLargeImpl(log, b, dirname, "")
}

// If dirname is set we write files there.
// Otherwise we use rootDir to estimate the size of the fileTag entries
func writeLargeImpl(log *base.LogObject, b []byte, dirname string, rootDir string) ([]byte, error) {
	var tree jsonTree

	err := json.Unmarshal(b, &tree)
	if err != nil {
		err := fmt.Errorf("writeLargeImpl: json.Unmarshal failed for %s: %v",
			dirname, err)
		return nil, err
	}
	tree, err = writeRemoveTree(log, tree, dirname, rootDir)
	if err != nil {
		return nil, err
	}
	log.Tracef("New tree: %+v", tree)
	b, err = json.Marshal(tree)
	if err != nil {
		err := fmt.Errorf("writeLargeImpl: json.Marshal failed for %s: %v",
			dirname, err)
		return nil, err
	}
	return b, nil
}

func writeRemoveTree(log *base.LogObject,
	tree jsonTree, dirname string, rootDir string) (jsonTree, error) {

	out := make(jsonTree)
	for k, v := range tree {
		if !strings.HasPrefix(k, tagLarge) {
			// descend into subtree if map
			tree1, ok := v.(jsonTree)
			if !ok {
				out[k] = v
				continue
			}
			log.Tracef("Descending into %s", k)
			tree1, err := writeRemoveTree(log, tree1, dirname, rootDir)
			if err != nil {
				return out, err
			}
			out[k] = tree1
			continue
		}
		oldTagLen := len(tagLarge)
		nk := tagFile + k[oldTagLen:]

		log.Tracef("tag %s type %T val %v\n", k, v, v)

		// We need to have a map to marshal (with a dummy tag -
		// we use k as the dummy), so that atoms and other values can be
		// consistently unmarshalled in readAddLarge()
		val := make(jsonTree)
		val[k] = v
		b, err := json.Marshal(val)
		if err != nil {
			err := fmt.Errorf("writeRemoveTree: Marshal failed for %s: %v",
				nk, err)
			return out, err
		}
		length := len(b)
		if length >= maxLargeLen {
			err := fmt.Errorf("too large string %d bytes for %s",
				length, k)
			return out, err
		}
		if dirname == "" {
			// Guess how much space a filename would take
			filename := rootDir + "0123456789012345678901234567890123456789012345678901234567890123456789"
			b, err := json.Marshal(filename)
			if err != nil {
				err := fmt.Errorf("writeRemoveTree: filename Marshal failed for %s: %v",
					filename, err)
				return out, err
			}
			out[nk] = string(b)
			continue
		}
		err = EnsureDir(dirname)
		if err != nil {
			err := fmt.Errorf("writeRemoveTree: EnsureDir failed for %s %s: %v",
				dirname, nk, err)
			return out, err
		}
		tmpfile, err := ioutil.TempFile(dirname, nk)
		if err != nil {
			err := fmt.Errorf("writeRemoveTree: TempFile failed for %s %s: %v",
				dirname, nk, err)
			return out, err
		}
		defer tmpfile.Close()
		filename := tmpfile.Name()

		_, err = tmpfile.Write(b)
		if err != nil {
			err := fmt.Errorf("writeRemoveTree: Write failed for %s %s: %v",
				dirname, nk, err)
			return out, err
		}
		tmpfile.Close()

		b, err = json.Marshal(filename)
		if err != nil {
			err := fmt.Errorf("writeRemoveTree: filename Marshal failed for %s: %v",
				filename, err)
			return out, err
		}
		out[nk] = string(b)
	}
	return out, nil
}

// EnsureDir to make sure it exists
func EnsureDir(dirname string) error {
	_, err := os.Stat(dirname)
	if err != nil {
		err := os.MkdirAll(dirname, 0755)
		if err != nil {
			return err
		}
	}
	return nil
}

// readAddLarge walks the json and uses readfile to fill in those fields which
// have a tagFile prefix.
// If there is an error it returns the input
func readAddLarge(log *base.LogObject, b []byte) ([]byte, error) {
	var tree jsonTree

	err := json.Unmarshal(b, &tree)
	if err != nil {
		err := fmt.Errorf("readAddLarge: json.Unmarshal failed: %v",
			err)
		return b, err
	}
	tree, err = readAddTree(log, tree)
	if err != nil {
		return b, err
	}
	log.Tracef("New tree: %+v", tree)
	out, err := json.Marshal(tree)
	if err != nil {
		err := fmt.Errorf("readAddLarge: json.Marshal failed: %v",
			err)
		return b, err
	}
	return out, nil
}

func readAddTree(log *base.LogObject, tree jsonTree) (jsonTree, error) {
	out := make(jsonTree)
	for k, v := range tree {
		if !strings.HasPrefix(k, tagFile) {
			// descend into subtree if map
			tree1, ok := v.(jsonTree)
			if !ok {
				out[k] = v
				continue
			}
			log.Tracef("Descending into %s", k)
			tree1, err := readAddTree(log, tree1)
			if err != nil {
				return out, err
			}
			out[k] = tree1
			continue
		}
		oldTagLen := len(tagFile)
		nk := tagLarge + k[oldTagLen:]

		str, ok := v.(string)
		if !ok {
			err := fmt.Errorf("readAddLarge: value not a string but %T for %s",
				v, k)
			return nil, err
		}
		log.Tracef("tag %s value: %s", k, str)
		var filename string
		err := json.Unmarshal([]byte(str), &filename)
		if err != nil {
			err := fmt.Errorf("readAddLarge: filename Unmarshal failed for %s: %v",
				k, err)
			return nil, err
		}
		str, _, err = fileutils.StatAndRead(log, filename, maxLargeLen+1)
		if err != nil {
			// XXX we handle not exists.
			if !os.IsNotExist(err) && err != io.EOF {
				err := fmt.Errorf("readAddLarge: failed for %s: %v",
					k, err)
				return nil, err
			}
		}
		os.Remove(filename)
		if len(str) == 0 {
			continue
		}
		log.Tracef("tag %s read %s content: %s", k, filename, str)
		var val jsonTree
		err = json.Unmarshal([]byte(str), &val)
		if err != nil {
			err := fmt.Errorf("readAddLarge: file content Unmarshal failed for %s: %v",
				filename, err)
			return nil, err
		}
		if len(val) != 1 {
			err := fmt.Errorf("readAddLarge: map read from file %s has %d keys for %s",
				filename, len(val), k)
			return nil, err
		}
		for _, v1 := range val {
			out[nk] = v1
		}
	}
	return out, nil
}
