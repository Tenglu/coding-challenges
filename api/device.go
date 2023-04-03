package api

import (
	"encoding/base64"
	"encoding/json"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/google/uuid"
	"net/http"
	"strconv"
)

type CreateSignatureDeviceRequest struct {
	ID        uuid.UUID `json:"id" required:"true"`
	Algorithm string    `json:"algorithm" required:"true"`
	Label     string    `json:"label,omitempty"`
}

type CreateSignatureDeviceResponse struct {
	ID uuid.UUID `json:"id"`
}

type SignTransactionRequest struct {
	ID   uuid.UUID `json:"id"`
	Data string    `json:"data" required:"true"`
}

type SignTransactionResponse struct {
	Signature  []byte `json:"signature"`
	SignedData []byte `json:"signed_data"`
}

// CreateSignatureDevice register signature device
func (s *Server) CreateSignatureDevice(response http.ResponseWriter, request *http.Request) {
	decoder := json.NewDecoder(request.Body)
	var createDeviceRequest CreateSignatureDeviceRequest
	err := decoder.Decode(&createDeviceRequest)
	if err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{"Invalid request payload"})
		return
	}

	if createDeviceRequest.ID == uuid.Nil {
		createDeviceRequest.ID = uuid.New()
	}
	device := domain.Device{
		ID:        createDeviceRequest.ID,
		Algorithm: createDeviceRequest.Algorithm,
		Label:     createDeviceRequest.Label,
	}
	switch device.Algorithm {
	case "ECC":
		eccGenerator := &crypto.ECCGenerator{}
		eccKeyPair, err := eccGenerator.Generate()
		if err != nil {
			WriteErrorResponse(response, http.StatusBadRequest, []string{"Error when generating ECC key pair"})
			return
		}
		eccMarshaller := crypto.NewECCMarshaler()
		_, device.PrivateKeyByte, err = eccMarshaller.Encode(*eccKeyPair)
		if err != nil {
			WriteErrorResponse(response, http.StatusBadRequest, []string{"Error when encoding ECC key pair"})
			return
		}
	case "RSA":
		rsaGenerator := &crypto.RSAGenerator{}
		rsaKeyPair, err := rsaGenerator.Generate()
		if err != nil {
			WriteErrorResponse(response, http.StatusBadRequest, []string{"Error when generating RSA key pair"})
			return
		}
		rsaMarshaller := crypto.NewRSAMarshaler()
		_, device.PrivateKeyByte, err = rsaMarshaller.Marshal(*rsaKeyPair)
		if err != nil {
			WriteErrorResponse(response, http.StatusBadRequest, []string{"Error when encoding RSA key pair"})
			return
		}
	}

	err = s.repository.Save(&device)
	if err != nil {
		return
	}
	createDeviceResponse := CreateSignatureDeviceResponse{
		ID: device.ID,
	}

	WriteAPIResponse(response, http.StatusCreated, createDeviceResponse)
}

// SignTransaction sign
func (s *Server) SignTransaction(response http.ResponseWriter, request *http.Request) {
	decoder := json.NewDecoder(request.Body)
	var signRequest SignTransactionRequest
	err := decoder.Decode(&signRequest)
	if err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{"Invalid request payload"})
		return
	}
	device, err := s.repository.FindByID(signRequest.ID)
	if err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{"The ID does not exit"})
		return
	}
	switch device.Algorithm {
	case "ECC":
		eccMarshaller := crypto.NewECCMarshaler()
		eccKeyPair, err := eccMarshaller.Decode(device.PrivateKeyByte)
		if err != nil {
			WriteErrorResponse(response, http.StatusBadRequest, []string{"Error when decoding ECC key pair:"})
			return
		}
		signer := crypto.NewECDSASigner(eccKeyPair.Private)
		signature, err := signer.Sign([]byte(signRequest.Data))
		if err != nil {
			WriteErrorResponse(response, http.StatusBadRequest, []string{"Cannot sign"})
			return
		}
		var lastSignature []byte
		device.LastSignature = []byte(base64.StdEncoding.EncodeToString(signature))
		lastSignature = device.LastSignature
		if device.Counter == 0 {
			lastSignature = []byte(base64.StdEncoding.EncodeToString([]byte(device.ID.String())))
		}
		SignResponse := SignTransactionResponse{
			Signature:  signature,
			SignedData: []byte(strconv.Itoa(device.Counter) + "_" + signRequest.Data + "_" + string(lastSignature)),
		}
		device.LastSignature = signature
		device.Counter++
		WriteAPIResponse(response, http.StatusCreated, SignResponse)
	case "RSA":
		rsaMarshaller := crypto.NewRSAMarshaler()
		rsaKeyPair, err := rsaMarshaller.Unmarshal(device.PrivateKeyByte)
		if err != nil {
			WriteErrorResponse(response, http.StatusBadRequest, []string{"Error when decoding ECC key pair:"})
			return
		}
		signer := crypto.NewRSASigner(rsaKeyPair.Private)
		signature, err := signer.Sign([]byte(signRequest.Data))
		if err != nil {
			WriteErrorResponse(response, http.StatusBadRequest, []string{"Cannot sign"})
			return
		}
		var lastSignature []byte
		device.LastSignature = []byte(base64.StdEncoding.EncodeToString(signature))
		lastSignature = device.LastSignature
		if device.Counter == 0 {
			lastSignature = []byte(base64.StdEncoding.EncodeToString([]byte(device.ID.String())))
		}
		SignResponse := SignTransactionResponse{
			Signature:  signature,
			SignedData: []byte(strconv.Itoa(device.Counter) + "_" + signRequest.Data + "_" + string(lastSignature)),
		}
		device.LastSignature = signature
		device.Counter++
		WriteAPIResponse(response, http.StatusCreated, SignResponse)
	}

}

// ListDevices returns the list of all devices.
func (s *Server) ListDevices(response http.ResponseWriter) {
	result, _ := s.repository.FindAll()
	WriteAPIResponse(response, http.StatusOK, result)
}
