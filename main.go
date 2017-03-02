// Copyright (c) 2017 Opsmate, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the
// sale, use or other dealings in this Software without prior written
// authorization.

package main

import (
	"archive/zip"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

type signedTreeHead struct {
	Version           int         `json:"sth_version"`
	TreeSize          uint64      `json:"tree_size"`
	Timestamp         uint64      `json:"timestamp"`
	SHA256RootHash    []byte      `json:"sha256_root_hash"`
	TreeHeadSignature []byte      `json:"tree_head_signature"`
	LogID             []byte      `json:"log_id"`
}

type sthPollen struct {
	STHs		[]*signedTreeHead `json:"sths"`
}

const sthSetAppId = "ojjgnpkioondelmggbekfhllhdaimnho"
const sthPathPrefix = "_platform_specific/all/sths/"

func readSTH(version int, logID []byte, file *zip.File) (*signedTreeHead, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("Failed to open sth in ZIP: %s\n", err)
	}
	defer reader.Close()
	sthBytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("Failed to read sth in ZIP: %s\n", err)
	}

	sth := &signedTreeHead{
		Version: version,
		LogID: logID,
	}
	if err := json.Unmarshal(sthBytes, sth); err != nil {
		return nil, fmt.Errorf("Failed to parse sth in ZIP: %s\n", err)
	}
	return sth, nil
}

func main() {
	z, err := fetchCRX(sthSetAppId)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching STH Set CRX: %s\n", err)
		os.Exit(1)
	}

	pollen := sthPollen{STHs: []*signedTreeHead{}}
	for _, file := range z.File {
		if strings.HasPrefix(file.Name, sthPathPrefix) && strings.HasSuffix(file.Name, ".sth") {
			logIDHex := strings.TrimSuffix(strings.TrimPrefix(file.Name, sthPathPrefix), ".sth")
			logID, err := hex.DecodeString(logIDHex)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Ignoring STH with bad filename: %s: %s\n", file.Name, err)
				continue
			}

			sth, err := readSTH(0, logID, file)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Ignoring invalid STH: %s: %s\n", file.Name, err)
				continue
			}
			pollen.STHs = append(pollen.STHs, sth)
		}
	}

	json.NewEncoder(os.Stdout).Encode(pollen)
}
