package loxonews

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/XciD/loxone_ws/crypto"
	"github.com/XciD/loxone_ws/events"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
)

const (
	getPublicKey                 = "jdev/sys/getPublicKey"
	keyExchange                  = "jdev/sys/keyexchange/%s"
	getUsersalt                  = "jdev/sys/getkey2/%s"
	getToken                     = "jdev/sys/gettoken/%s/%s/%d/%s/%s" // #nosec
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

// LoxoneRoom represent a room
type LoxoneRoom struct {
	Name string
	UUID string
	Type int32
}

// LoxoneCategory represent a category
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
	encrypt  *encrypt
	token    *loxoneToken
	// Events received from the websockets
	Events         chan *events.Event
	registerEvents bool

	internalCmdChan chan *websocketResponse
	Socket          *websocket.Conn
	disconnect      chan bool
}

type websocketResponse struct {
	data         *[]byte
	responseType events.EventType
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
		err := mapstructure.Decode(ll["value"], &class)

		if err != nil {
			return nil, err
		}
	}

	return body, nil
}

// Connect to the loxone websocket
func Connect(host string, user string, password string) (*Loxone, error) {
	if host == "" || user == "" || password == "" {
		return nil, errors.New("missing host / user / password")
	}

	loxone := &Loxone{
		host:            host,
		user:            user,
		password:        password,
		registerEvents:  false,
		Events:          make(chan *events.Event),
		internalCmdChan: make(chan *websocketResponse),
		disconnect:      make(chan bool),
	}

	err := loxone.connect()

	if err != nil {
		return nil, err
	}

	return loxone, nil
}

func (l *Loxone) connect() error {
	err := l.connectWs()

	if err != nil {
		return err
	}

	err = l.authenticate()

	if err != nil {
		return err
	}

	// Handle disconnect
	go l.handleReconnect()

	return nil
}

func (l *Loxone) handleReconnect() {
	// If we finish, we restart a reconnect loop
	for range l.disconnect {
		for {
			log.Warn("Disconnected, reconnecting")
			time.Sleep(30 * time.Second)

			err := l.connect()

			if err != nil {
				log.Warn("Error during reconnection, retrying")
				continue
			}

			if l.registerEvents {
				_ = l.RegisterEvents()
			}
			break
		}
		break
	}
}

// RegisterEvents ask the loxone server to send events
func (l *Loxone) RegisterEvents() error {
	l.registerEvents = true

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
	uniqueID := crypto.CreateEncryptKey(32)
	ivKey := crypto.CreateEncryptKey(16)

	// encrypt both and send them to server to get a Salt
	cipherMessage, err := crypto.EncryptWithPublicKey([]byte(fmt.Sprintf("%s:%s", uniqueID, ivKey)), publicKey)

	if err != nil {
		return err
	}

	log.Info("Key Exchange with Miniserver")
	resultValue := &LoxoneSimpleValue{}
	_, err = l.sendCmdWithEnc(fmt.Sprintf(keyExchange, cipherMessage), none, resultValue)

	if err != nil {
		return err
	}

	salt, err := crypto.DecryptAES(resultValue.Value, uniqueID, ivKey)

	if err != nil {
		return err
	}

	l.encrypt = &encrypt{
		publicKey:   publicKey,
		key:         uniqueID,
		iv:          ivKey,
		oneTimeSalt: string(salt),
		timestamp:   time.Now(),
		salt:        crypto.CreateEncryptKey(2),
	}

	log.Info("Key Exchange OK")
	log.Info("Authentication Starting")

	err = l.createToken(l.user, l.password, uniqueID)

	if err != nil {
		return err
	}

	log.Info("Authentication OK")

	return nil
}

func (l *Loxone) sendCmdWithEnc(cmd string, encryptType encryptType, class interface{}) (*LoxoneBody, error) {
	encryptedCmd, err := l.encrypt.getEncryptedCmd(cmd, encryptType)

	if err != nil {
		return nil, err
	}

	result, err := l.sendSocketCmd(&encryptedCmd)

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
		if result.responseType == events.EventTypeText {
			body, err := deserializeLoxoneResponse(result.data, class)

			if err != nil {
				return nil, err
			}

			if body.Code != 200 {
				return nil, fmt.Errorf("error server, code: %d", body.Code)
			}
			return body, nil
		} else if result.responseType == events.EventTypeFile {
			err := json.Unmarshal(*result.data, &class)
			if err != nil {
				return nil, err
			}
			// Response is copied to class
			return nil, nil
		}
		return nil, fmt.Errorf("unHandled response type: %d", result.responseType)
	}

	log.Debug(string(*result.data))
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

func (l *Loxone) connectWs() error {
	u := url.URL{Scheme: "ws", Host: l.host, Path: "/ws/rfc6455?_=" + strconv.FormatInt(time.Now().Unix(), 10)}

	socket, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	l.Socket = socket
	if err != nil {
		return err
	}
	go func() {
		defer func() {
			log.Warn("Closing Socket")
			defer socket.Close()
			err := l.Socket.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("write closeWs:", err)
				return
			}
		}()
		l.listenWs()
	}()

	return nil
}

func (l *Loxone) listenWs() {
	incomingData := events.EmptyHeader

	for {
		_, message, err := l.Socket.ReadMessage()
		if err != nil {
			log.Error("read error:", err)
			l.disconnect <- true
			return
		}
		// Check if we received an header or not
		if len(message) == 8 {
			// we got an LX-Bin-header!
			incomingData, err = events.IdentifyHeader(message)
			if err != nil {
				log.Debugf("Error during identify header %v", err)
				incomingData = events.EmptyHeader
			} else if incomingData.Length == 0 && incomingData.EventType != events.EventTypeOutofservice && incomingData.EventType != events.EventTypeKeepalive {
				log.Debug("received header telling 0 bytes payload - resolve request with null!")
				// TODO sendOnBinaryMessage
				incomingData = events.EmptyHeader
			} else {
				log.Debugf("Received header: %+v\n", incomingData)

				if incomingData.EventType == events.EventTypeOutofservice {
					log.Warn("Miniserver out of service!")
					l.disconnect <- true
					break
				}

				if incomingData.EventType == events.EventTypeKeepalive {
					log.Debug("KeepAlive")
					incomingData = events.EmptyHeader
					continue
				}
				// Waiting for the data
				continue
			}

		} else if !incomingData.Empty && incomingData.Length == len(message) {
			// Received message
			switch incomingData.EventType {
			case events.EventTypeText:
				log.Debug("Received a text message from previous header")
				l.internalCmdChan <- &websocketResponse{data: &message, responseType: incomingData.EventType}
			case events.EventTypeFile:
				log.Debug("Received a file from previous header")
				l.internalCmdChan <- &websocketResponse{data: &message, responseType: incomingData.EventType}
			case events.EventTypeEvent:
				l.handleBinaryEvent(&message, incomingData.EventType)
			case events.EventTypeEventtext:
				l.handleBinaryEvent(&message, incomingData.EventType)
			case events.EventTypeDaytimer:
				l.handleBinaryEvent(&message, incomingData.EventType)
			case events.EventTypeWeather:
				l.handleBinaryEvent(&message, incomingData.EventType)
			default:
				log.Warnf("Unknown event %d", incomingData.EventType)
			}

			incomingData = events.EmptyHeader
		} else {
			log.Debug("Received binary message without header ")
			// TODO Send to error
		}
	}
}

func (l *Loxone) handleBinaryEvent(binaryEvent *[]byte, eventType events.EventType) {
	events := events.InitBinaryEvent(binaryEvent, eventType)

	for _, event := range events.Events {
		l.Events <- event
	}
}

func (l *Loxone) sendSocketCmd(cmd *[]byte) (*websocketResponse, error) {
	log.Debug("Sending commande to WS")
	err := l.Socket.WriteMessage(websocket.TextMessage, *cmd)

	if err != nil {
		return nil, err
	}

	log.Debug("Waiting for answer")
	result := <-l.internalCmdChan
	log.Debugf("WS answered")
	return result, nil
}

func (e *encrypt) hashUser(user string, password string, salt string, oneTimeSalt string) string {
	// create a SHA1 hash of the (salted) password
	hash := strings.ToUpper(crypto.Sha1Hash(fmt.Sprintf("%s:%s", password, salt)))

	// hash with user and otSalt
	hash = crypto.ComputeHmac256(fmt.Sprintf("%s:%s", user, hash), oneTimeSalt)

	return hash
}

func (e *encrypt) getEncryptedCmd(cmd string, encryptType encryptType) ([]byte, error) {
	if encryptType == none {
		return []byte(cmd), nil
	}

	// TODO code next Salt
	cmd = fmt.Sprintf(aesPayload, e.salt, cmd)
	cipher, err := crypto.EncryptAES(cmd, e.key, e.iv)

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
	return crypto.DecryptAES(string(cipherText), e.key, e.iv)
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
		return nil, errors.New("pub key is empty")
	}

	return crypto.BytesToPublicKey(publicKey.Value)
}
