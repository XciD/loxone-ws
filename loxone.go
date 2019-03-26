package loxonews

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
)

const (
	getPublicKey                 = "jdev/sys/getPublicKey"
	keyExchange                  = "jdev/sys/keyexchange/%s"
	getUsersalt                  = "jdev/sys/getkey2/%s"
	getToken                     = "jdev/sys/gettoken/%s/%s/%d/%s/%s"
	aesPayload                   = "salt/%s/%s"
	encryptionCmd                = "jdev/sys/enc/%s"
	encryptionCommandAndResponse = "jdev/sys/fenc/%s"
	registerEvents               = "jdev/sps/enablebinstatusupdate"
	getConfig                    = "data/LoxAPP3.json"
)

// LoxoneBody response form command sent by ws
type LoxoneBody struct {
	// Control name of the control invoked
	Control string
	// Code status
	Code int32
}

// LoxoneSimpleValue represent a simple Loxone Response Value
type LoxoneSimpleValue struct {
	// The value answered
	Value string
}

// LoxoneConfig represent the LoxAPP3.json config file
type LoxoneConfig struct {
	// LastModified
	LastModified string
	// MsInfo
	MsInfo map[string]interface{}
	// GlobalStates states about the sun, the day, etc
	GlobalStates map[string]string
	// OperatingModes of the loxone server
	OperatingModes map[string]interface{}
	// Rooms of the loxone server
	Rooms map[string]*LoxoneRoom
	// Cats Categories of the loxone server
	Cats map[string]*LoxoneCategory
	// Controls all the control of the loxone server
	Controls map[string]*LoxoneControl
}

// LoxoneControl represent a control
type LoxoneControl struct {
	Name       string
	Type       string
	UUIDAction string
	Room       string
	Cat        string
	States     map[string]interface{} // Can be an array or a string
}

type LoxoneRoom struct {
	Name string
	UUID string
	Type int32
}

type LoxoneCategory struct {
	Name string
	UUID string
	Type string
}

// Loxone The loxone object exposed
type Loxone struct {
	host     string
	user     string
	password string
	socket   *loxoneWebsocket
	encrypt  *encrypt
	token    *loxoneToken
	// Events received from the websockets
	Events chan *Event
}

type encrypt struct {
	publicKey   *rsa.PublicKey
	key         string
	iv          string
	timestamp   time.Time
	oneTimeSalt string
	salt        string
}

type loxoneToken struct {
	token        string
	key          string
	validUntil   int64
	tokenRights  int32
	unsecurePass bool
}

type loxoneSalt struct {
	OneTimeSalt string `mapstructure:"key"`
	Salt        string `mapstructure:"Salt"`
}

type encryptType int32

const (
	none encryptType = 0
	//request            encryptType = 1
	requestResponseVal encryptType = 2
)

func deserializeLoxoneResponse(jsonBytes *[]byte, class interface{}) (*LoxoneBody, error) {
	raw := make(map[string]interface{})
	err := json.Unmarshal(*jsonBytes, &raw)
	if err != nil {
		return nil, err
	}

	ll := raw["LL"].(map[string]interface{})

	body := &LoxoneBody{Control: ll["control"].(string)}

	var code interface{}
	// If can be on Code or code...
	if val, ok := ll["Code"]; ok {
		code = val
	}
	if val, ok := ll["code"]; ok {
		code = val
	}

	// Can be a string or a float...
	switch code.(type) {
	case string:
		i, _ := strconv.ParseInt(code.(string), 10, 32)
		body.Code = int32(i)
	case float64:
		body.Code = int32(code.(float64))
	}

	// Deserialize value
	switch ll["value"].(type) {
	case string:
		rv := reflect.ValueOf(class).Elem()
		rv.FieldByName("Value").SetString(ll["value"].(string))
	case map[string]interface{}:
		mapstructure.Decode(ll["value"], &class)
	}

	return body, nil
}

// Connect to the loxone websocket
func Connect(host string, user string, password string) (*Loxone, error) {
	socket := createSocket(host)
	socket.connect()

	loxone := &Loxone{
		host:     host,
		user:     user,
		password: password,
		socket:   socket,
		Events:   socket.events,
	}

	err := loxone.authenticate()

	if err != nil {
		return nil, err
	}

	return loxone, nil
}

// RegisterEvents ask the loxone server to send events
func (l *Loxone) RegisterEvents() error {
	_, err := l.SendCommand(registerEvents, nil)

	if err != nil {
		return err
	}

	return nil
}

// GetConfig get the loxone server config
func (l *Loxone) GetConfig() (*LoxoneConfig, error) {
	config := &LoxoneConfig{}

	_, err := l.SendCommand(getConfig, config)

	if err != nil {
		return nil, err
	}

	return config, nil
}

// SendCommand Send a command to the loxone server
func (l *Loxone) SendCommand(cmd string, class interface{}) (*LoxoneBody, error) {
	return l.sendCmdWithEnc(cmd, none, class)
}

func (l *Loxone) authenticate() error {
	// Retrieve public key
	log.Info("Asking for Public Key")
	publicKey, err := getPublicKeyFromServer(l.host)

	if err != nil {
		return err
	}

	log.Info("Public Key OK")

	// Create an unique key and an iv for AES
	uniqueID := createEncryptKey(32)
	ivKey := createEncryptKey(16)

	// encrypt both and send them to server to get a Salt
	cipherMessage, err := encryptWithPublicKey([]byte(fmt.Sprintf("%s:%s", uniqueID, ivKey)), publicKey)

	if err != nil {
		return err
	}

	log.Info("Key Exchange with Miniserver")
	resultValue := &LoxoneSimpleValue{}
	_, err = l.sendCmdWithEnc(fmt.Sprintf(keyExchange, cipherMessage), none, resultValue)

	if err != nil {
		return err
	}

	salt, err := decryptAES(resultValue.Value, uniqueID, ivKey)

	l.encrypt = &encrypt{
		publicKey:   publicKey,
		key:         uniqueID,
		iv:          ivKey,
		oneTimeSalt: string(salt),
		timestamp:   time.Now(),
		salt:        createEncryptKey(2),
	}

	if err != nil {
		return err
	}

	log.Info("Key Exchange OK")
	log.Info("Authentication Starting")

	l.createToken(l.user, l.password, uniqueID)

	return nil
}

func (l *Loxone) sendCmdWithEnc(cmd string, encryptType encryptType, class interface{}) (*LoxoneBody, error) {
	encryptedCmd, err := l.encrypt.getEncryptedCmd(cmd, encryptType)

	if err != nil {
		return nil, err
	}

	result, err := l.socket.sendCmd(&encryptedCmd)

	if err != nil {
		return nil, err
	}

	if encryptType == requestResponseVal {
		// We need to decrypt
		decryptedResult, err := l.encrypt.decryptCmd(*result.data)
		if err != nil {
			return nil, err
		}
		result.data = &decryptedResult
	}

	if class != nil {
		if result.responseType == text {
			body, err := deserializeLoxoneResponse(result.data, class)

			if err != nil {
				return nil, err
			}

			if body.Code != 200 {
				return nil, fmt.Errorf("error server, code: %d", body.Code)
			}
			return body, nil
		} else if result.responseType == file {
			err := json.Unmarshal(*result.data, &class)
			if err != nil {
				return nil, err
			}
			// Response is copied to class
			return nil, nil
		}
		return nil, fmt.Errorf("unHandled response type: %d", result.responseType)
	}

	return &LoxoneBody{Code: 200}, nil
}

func (l *Loxone) createToken(user string, password string, uniqueID string) error {
	cmd := fmt.Sprintf(getUsersalt, user)

	salt := &loxoneSalt{}
	_, err := l.sendCmdWithEnc(cmd, requestResponseVal, salt)

	if err != nil {
		return err
	}

	hash := l.encrypt.hashUser(user, password, salt.Salt, salt.OneTimeSalt)

	cmd = fmt.Sprintf(getToken, hash, user, 4, uniqueID, "GO")

	token := &loxoneToken{}
	_, err = l.sendCmdWithEnc(cmd, requestResponseVal, token)

	if err != nil {
		return err
	}

	l.token = token
	return nil
}

func (e *encrypt) hashUser(user string, password string, salt string, oneTimeSalt string) string {
	// create a SHA1 hash of the (salted) password
	hash := strings.ToUpper(sha1Hash(fmt.Sprintf("%s:%s", password, salt)))

	// hash with user and otSalt
	hash = computeHmac256(fmt.Sprintf("%s:%s", user, hash), oneTimeSalt)

	return hash
}

func (e *encrypt) getEncryptedCmd(cmd string, encryptType encryptType) ([]byte, error) {
	if encryptType == none {
		return []byte(cmd), nil
	}

	// TODO code next Salt
	cmd = fmt.Sprintf(aesPayload, e.salt, cmd)
	cipher, err := encryptAES(cmd, e.key, e.iv)

	if err != nil {
		return nil, err
	}

	format := encryptionCmd
	if encryptType == requestResponseVal {
		format = encryptionCommandAndResponse
	}

	escape := fmt.Sprintf(format, url.QueryEscape(cipher))
	return []byte(escape), nil
}

func (e *encrypt) decryptCmd(cipherText []byte) ([]byte, error) {
	return decryptAES(string(cipherText), e.key, e.iv)
}

func getPublicKeyFromServer(url string) (*rsa.PublicKey, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/%s", url, getPublicKey), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	publicKey := &LoxoneSimpleValue{}
	_, err = deserializeLoxoneResponse(&body, publicKey)

	if err != nil {
		return nil, err
	}

	if publicKey.Value == "" {
		return nil, errors.New("Error, pub key is empty")
	}

	return bytesToPublicKey(publicKey.Value)
}
