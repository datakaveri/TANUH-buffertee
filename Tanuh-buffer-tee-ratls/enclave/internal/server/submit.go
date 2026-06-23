package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	cryptosha256 "crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/datakaveri/tanuh-buffer-tee/internal/bundle"
	hpkepkg "github.com/datakaveri/tanuh-buffer-tee/internal/hpke"
)

const (
	maxHeaderBytes = 8192
	maxTotalChunks = 16384
	aesKeyLen      = 32
)

// JobRequest is the small HPKE-encrypted metadata payload.
// Model bytes are NOT included — they are uploaded separately via /v1/upload.
// SHA256 hashes commit to the files before they arrive (prevents in-transit swaps).
type JobRequest struct {
	DatasetID           int    `json:"dataset_id"`               // 1, 2, or 3
	ModelSHA256         string `json:"model_sha256"`             // hex SHA256 of model.onnx plaintext
	WeightsSHA256       string `json:"weights_sha256"`           // hex SHA256 of weights plaintext
	PreprocessingSHA256 string `json:"preprocessing_sha256,omitempty"` // hex SHA256 of preprocessing.py (dataset_id=2)
}

// ChunkedUploadHeader is Frame 0 of the AES-256-GCM-CHUNKED-v1 stream.
type ChunkedUploadHeader struct {
	FileID          string `json:"file_id"`
	Enc             string `json:"enc"`              // base64std HPKE encapsulated key (32 bytes)
	WrappedKey      string `json:"wrapped_key"`      // base64std HPKE-wrapped AES-256 key (48 bytes)
	BaseIV          string `json:"base_iv"`          // base64std 12-byte base IV; chunk i uses BaseIV+i (96-bit big-endian)
	TotalChunks     int    `json:"total_chunks"`
	PlaintextSHA256 string `json:"plaintext_sha256"` // hex SHA256 of assembled plaintext
}

// HandleSubmit serves POST /v1/submit.
// Receives HPKE-encrypted metadata only — no model bytes in this call.
// Returns {job_id, status} encrypted back to browser.
func (s *Server) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	browserPubB64u := r.Header.Get("X-RATLS-Browser-HPKE")
	if browserPubB64u == "" {
		http.Error(w, "missing X-RATLS-Browser-HPKE header", http.StatusBadRequest)
		return
	}
	browserPubBytes, err := base64.RawURLEncoding.DecodeString(browserPubB64u)
	if err != nil || len(browserPubBytes) != 32 {
		http.Error(w, "bad X-RATLS-Browser-HPKE: must be 32-byte base64url", http.StatusBadRequest)
		return
	}

	// 1 MB limit — metadata only, no model bytes
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var req bundle.EncryptedRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	encBytes, err := base64.StdEncoding.DecodeString(req.Enc)
	if err != nil {
		http.Error(w, "bad enc", http.StatusBadRequest)
		return
	}
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, "bad ciphertext", http.StatusBadRequest)
		return
	}
	aad, err := base64.StdEncoding.DecodeString(req.AAD)
	if err != nil {
		http.Error(w, "bad aad", http.StatusBadRequest)
		return
	}

	hpkePriv, hpkePub := s.builder.HPKEKeys()
	info := hpkepkg.ContextInfo(hpkePub.Bytes(), browserPubBytes)

	plaintext, err := hpkepkg.OpenFromBrowser(hpkePriv, encBytes, info, aad, ct)
	if err != nil {
		http.Error(w, "decryption failed", http.StatusBadRequest)
		return
	}

	response := processJob(plaintext)

	rid := r.Header.Get("X-Request-Id")
	respAAD := []byte(fmt.Sprintf(`{"rid":%q,"ts":%d}`, rid, time.Now().Unix()))

	sealed, err := hpkepkg.SealToBrowser(browserPubBytes, info, respAAD, response)
	if err != nil {
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bundle.EncryptedResponse{ //nolint:errcheck
		Enc:        base64.StdEncoding.EncodeToString(sealed.Enc),
		Ciphertext: base64.StdEncoding.EncodeToString(sealed.Ciphertext),
		AAD:        base64.StdEncoding.EncodeToString(respAAD),
	})
}

// HandleUploadModel serves PUT /v1/upload/{job_id}/model.
// Decrypts AES-256-GCM-CHUNKED-v1 stream, verifies SHA-256, forwards plaintext to Flask.
func (s *Server) HandleUploadModel(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("job_id")
	plaintext, err := s.decryptChunkedUpload(r.Body, r.Header.Get("X-RATLS-Browser-HPKE"))
	if err != nil {
		log.Printf("model upload decrypt %s: %v", jobID, err)
		http.Error(w, "decryption failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	proxyPlaintextUpload(w, bufferManagerURL+"/buffer/jobs/"+jobID+"/model", plaintext)
}

// HandleUploadWeights serves PUT /v1/upload/{job_id}/weights.
func (s *Server) HandleUploadWeights(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("job_id")
	plaintext, err := s.decryptChunkedUpload(r.Body, r.Header.Get("X-RATLS-Browser-HPKE"))
	if err != nil {
		log.Printf("weights upload decrypt %s: %v", jobID, err)
		http.Error(w, "decryption failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	proxyPlaintextUpload(w, bufferManagerURL+"/buffer/jobs/"+jobID+"/weights", plaintext)
}

// HandleUploadPreprocessing serves PUT /v1/upload/{job_id}/preprocessing.
// Decrypts the user's preprocessing.py and forwards plaintext to Flask.
func (s *Server) HandleUploadPreprocessing(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("job_id")
	plaintext, err := s.decryptChunkedUpload(r.Body, r.Header.Get("X-RATLS-Browser-HPKE"))
	if err != nil {
		log.Printf("preprocessing upload decrypt %s: %v", jobID, err)
		http.Error(w, "decryption failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	proxyPlaintextUpload(w, bufferManagerURL+"/buffer/jobs/"+jobID+"/preprocessing", plaintext)
}

// decryptChunkedUpload reads and decrypts an AES-256-GCM-CHUNKED-v1 framed stream.
//
// Wire format:
//
//	[4 bytes big-endian: header JSON length]
//	[header JSON]
//	for each chunk i in 0..totalChunks-1:
//	  [4 bytes big-endian: ciphertext length]
//	  [ciphertext bytes]  (plaintext + 16-byte GCM tag)
//
// Per-chunk IV: baseIV + i (96-bit big-endian increment of the 12-byte base IV)
// Per-chunk AAD:   "{i}:{totalChunks}:{fileId}" as UTF-8
func (s *Server) decryptChunkedUpload(body io.Reader, browserPubB64u string) ([]byte, error) {
	if browserPubB64u == "" {
		return nil, fmt.Errorf("missing X-RATLS-Browser-HPKE header")
	}
	browserPubBytes, err := base64.RawURLEncoding.DecodeString(browserPubB64u)
	if err != nil || len(browserPubBytes) != 32 {
		return nil, fmt.Errorf("bad X-RATLS-Browser-HPKE")
	}

	// Frame 0: 4-byte header length + header JSON
	var headerLen uint32
	if err := binary.Read(body, binary.BigEndian, &headerLen); err != nil {
		return nil, fmt.Errorf("read header length: %w", err)
	}
	if headerLen == 0 || headerLen > maxHeaderBytes {
		return nil, fmt.Errorf("invalid header length: %d", headerLen)
	}
	headerBytes := make([]byte, headerLen)
	if _, err := io.ReadFull(body, headerBytes); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	var hdr ChunkedUploadHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	if hdr.TotalChunks <= 0 || hdr.TotalChunks > maxTotalChunks {
		return nil, fmt.Errorf("invalid total_chunks: %d", hdr.TotalChunks)
	}
	if hdr.FileID == "" {
		return nil, fmt.Errorf("missing file_id")
	}

	// Decode HPKE-wrapped AES key
	encBytes, err := base64.StdEncoding.DecodeString(hdr.Enc)
	if err != nil {
		return nil, fmt.Errorf("decode enc: %w", err)
	}
	wrappedKey, err := base64.StdEncoding.DecodeString(hdr.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped_key: %w", err)
	}
	baseIV, err := base64.StdEncoding.DecodeString(hdr.BaseIV)
	if err != nil || len(baseIV) != 12 {
		return nil, fmt.Errorf("bad base_iv: must be 12 bytes")
	}

	// HPKE-unwrap the symmetric key (no AAD — key wrapping uses info binding only)
	hpkePriv, hpkePub := s.builder.HPKEKeys()
	info := hpkepkg.ContextInfo(hpkePub.Bytes(), browserPubBytes)
	aesKeyBytes, err := hpkepkg.OpenFromBrowser(hpkePriv, encBytes, info, nil, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("hpke key unwrap: %w", err)
	}
	if len(aesKeyBytes) != aesKeyLen {
		return nil, fmt.Errorf("unwrapped key wrong length: %d", len(aesKeyBytes))
	}

	// Import AES-256-GCM; zero key bytes immediately after
	block, err := aes.NewCipher(aesKeyBytes)
	for i := range aesKeyBytes {
		aesKeyBytes[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	// Decrypt chunks; nonce starts at baseIV and increments by 1 (big-endian) each chunk.
	nonce := make([]byte, 12)
	copy(nonce, baseIV)
	var assembled []byte

	for i := 0; i < hdr.TotalChunks; i++ {
		var chunkLen uint32
		if err := binary.Read(body, binary.BigEndian, &chunkLen); err != nil {
			return nil, fmt.Errorf("read chunk %d length: %w", i, err)
		}
		ct := make([]byte, chunkLen)
		if _, err := io.ReadFull(body, ct); err != nil {
			return nil, fmt.Errorf("read chunk %d data: %w", i, err)
		}

		aad := []byte(fmt.Sprintf("%d:%d:%s", i, hdr.TotalChunks, hdr.FileID))

		pt, err := gcm.Open(nil, nonce, ct, aad)
		if err != nil {
			return nil, fmt.Errorf("chunk %d authentication failed", i)
		}
		assembled = append(assembled, pt...)

		// increment nonce by 1 (big-endian, with carry) for the next chunk
		for j := 11; j >= 0; j-- {
			nonce[j]++
			if nonce[j] != 0 {
				break
			}
		}
	}

	// Verify SHA-256 of assembled plaintext against header commitment
	if hdr.PlaintextSHA256 != "" {
		digest := cryptosha256.Sum256(assembled)
		if hex.EncodeToString(digest[:]) != hdr.PlaintextSHA256 {
			return nil, fmt.Errorf("plaintext sha256 mismatch")
		}
	}

	log.Printf("chunked upload: decrypted %d bytes in %d chunks (file_id=%s)",
		len(assembled), hdr.TotalChunks, hdr.FileID)
	return assembled, nil
}

// proxyPlaintextUpload PUTs decrypted plaintext bytes to Flask.
func proxyPlaintextUpload(w http.ResponseWriter, url string, data []byte) {
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		http.Error(w, "proxy error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(data))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("upload proxy %s: %v", url, err)
		http.Error(w, "buffer manager unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

func processJob(plaintext []byte) []byte {
	var jobReq JobRequest
	if err := json.Unmarshal(plaintext, &jobReq); err != nil {
		return jsonErr("invalid job payload: " + err.Error())
	}
	if jobReq.DatasetID < 1 || jobReq.DatasetID > 3 {
		return jsonErr("dataset_id must be 1, 2, or 3")
	}

	flaskData := map[string]interface{}{
		"dataset_id":     jobReq.DatasetID,
		"model_sha256":   jobReq.ModelSHA256,
		"weights_sha256": jobReq.WeightsSHA256,
	}
	if jobReq.PreprocessingSHA256 != "" {
		flaskData["preprocessing_sha256"] = jobReq.PreprocessingSHA256
	}
	flaskPayload, _ := json.Marshal(flaskData)

	resp, err := http.Post(bufferManagerURL+"/buffer/jobs", "application/json", //nolint:noctx
		bytes.NewReader(flaskPayload))
	if err != nil {
		log.Printf("submit: buffer-manager: %v", err)
		return jsonErr("buffer manager unavailable: " + err.Error())
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	log.Printf("submit: buffer-manager %d", resp.StatusCode)
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return jsonErr(fmt.Sprintf("buffer manager error %d: %s", resp.StatusCode, string(respBody)))
	}
	return respBody
}

func jsonErr(msg string) []byte {
	b, _ := json.Marshal(map[string]string{"status": "error", "message": msg})
	return b
}
