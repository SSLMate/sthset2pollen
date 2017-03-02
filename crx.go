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
//
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
// * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// buildCRXURL returns a URL from which the latest version of a CRX can be fetched.
func buildCrxURL(appid string) string {
	args := url.Values(make(map[string][]string))
	args.Add("response", "redirect")
	args.Add("x", "id="+appid+"&uc")

	return (&url.URL{
		Scheme:   "http",
		Host:     "clients2.google.com",
		Path:     "/service/update2/crx",
		RawQuery: args.Encode(),
	}).String()
}

// crxHeader reflects the binary header of a CRX file.
type crxHeader struct {
	Magic       [4]byte
	Version     uint32
	PubKeyBytes uint32
	SigBytes    uint32
}

// zipReader is a small wrapper around a []byte which implements ReadAt.
type zipReader []byte

func (z zipReader) ReadAt(p []byte, pos int64) (int, error) {
	if int(pos) < 0 {
		return 0, nil
	}
	return copy(p, []byte(z)[int(pos):]), nil
}

func fetchCRX(appid string) (*zip.Reader, error) {
	resp, err := http.Get(buildCrxURL(appid))
	if err != nil {
		return nil, fmt.Errorf("Failed to get CRX: %s", err)
	}
	defer resp.Body.Close()

	// zip needs to seek around, so we read the whole reply into memory.
	crxBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to download CRX: %s", err)
	}
	crx := bytes.NewBuffer(crxBytes)

	var header crxHeader
	if err := binary.Read(crx, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("Failed to parse CRX header: %s", err)
	}

	if !bytes.Equal(header.Magic[:], []byte("Cr24")) ||
		int(header.PubKeyBytes) < 0 ||
		int(header.SigBytes) < 0 {
		return nil, fmt.Errorf("Downloaded file doesn't look like a CRX")
	}

	pubKeyBytes := crx.Next(int(header.PubKeyBytes))
	sigBytes := crx.Next(int(header.SigBytes))

	if len(pubKeyBytes) != int(header.PubKeyBytes) ||
		len(sigBytes) != int(header.SigBytes) {
		return nil, fmt.Errorf("Downloaded file doesn't look like a CRX")
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse public key: %s", err)
	}
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Not signed with an RSA key")
	}

	h := sha256.New()
	h.Write(pubKeyBytes)
	pubKeyHash := fmt.Sprintf("%x", h.Sum(nil)[:16])
	tweakedPubKeyHash := make([]byte, len(pubKeyHash))

	// AppIds use a different hex character set so we convert our hash into
	// it.
	for i := range pubKeyHash {
		if pubKeyHash[i] < 97 {
			tweakedPubKeyHash[i] = pubKeyHash[i] + 49
		} else {
			tweakedPubKeyHash[i] = pubKeyHash[i] + 10
		}
	}

	if string(tweakedPubKeyHash) != appid {
		return nil, fmt.Errorf("Public key mismatch (%s)", tweakedPubKeyHash)
	}

	zipBytes := crx.Bytes()

	sha1Hash := sha1.New()
	sha1Hash.Write(zipBytes)

	if err := rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA1, sha1Hash.Sum(nil), sigBytes); err != nil {
		return nil, fmt.Errorf("Signature verification failure: %s", err)
	}

	zipReader := zipReader(zipBytes)

	z, err := zip.NewReader(zipReader, int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("Failed to parse ZIP file: %s", err)
	}

	return z, nil
}
