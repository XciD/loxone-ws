package loxone

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

	"github.com/XciD/loxone-ws/crypto"
	"github.com/XciD/loxone-ws/events"

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

// Body response form command sent by ws
type Body struct {
	// Control name of the control invoked
	Control string
	// Code status
	Code int32
}

// SimpleValue represent a simple Loxone Response Value
type SimpleValue struct {
	// The value answered
	Value string
}

// Config represent the LoxAPP3.json config file
type Config struct {
	// LastModified
	LastModified string
	// MsInfo
	MsInfo map[string]interface{}
	// GlobalStates states about the sun, the day, etc
	GlobalStates map[string]string
	// OperatingModes of the loxone server
	OperatingModes map[string]interface{}
	// Rooms of the loxone server
	Rooms map[string]*Room
	// Cats Categories of the loxone server
	Cats map[string]*Category
	// Controls all the control of the loxone server
	Controls map[string]*Control
}

func (cfg *Config) CatName(key interface{}) string {
	k, ok := key.(string)
	if !ok {
		return ""
	}
	cat, ok := cfg.Cats[k]
	if !ok {
		return ""
	}
	return cat.Name
}

func (cfg *Config) RoomName(key interface{}) string {
	k, ok := key.(string)
	if !ok {
		return ""
	}
	room, ok := cfg.Rooms[k]
	if !ok {
		return ""
	}
	return room.Name
}

// Control represent a control
type Control struct {
	Name       string
	Type       string
	UUIDAction string
	IsFavorite bool `json:"isFavorite"`
	Room       string
	Cat        string
	States     map[string]interface{} // Can be an array or a string
}

// Room represent a room
type Room struct {
	Name string
	UUID string
	Type int32
}

// Category represent a category
type Category struct {
	Name string
	UUID string
	Type string
}

// Loxone The loxone object exposed
type Loxone struct {
	host            string
	user            string
	password        string
	encrypt         *encrypt
	token           *token
	Events          chan *events.Event
	callbackChannel chan *websocketResponse
	socketMessage   chan *[]byte
	socket          *websocket.Conn
	disconnected    chan bool
	stop            chan bool
	hooks           map[string]func(*events.Event)
	registerEvents  bool
}

type WebsocketInterface interface {
	AddHook(uuid string, callback func(*events.Event))
	SendCommand(command string, class interface{}) (*Body, error)
	Close()
	RegisterEvents() error
	PumpEvents(stop <-chan bool)
	GetConfig() (*Config, error)
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

type token struct {
	token        string
	key          string
	validUntil   int64
	tokenRights  int32
	unsecurePass bool
}

type salt struct {
	OneTimeSalt string `mapstructure:"key"`
	Salt        string `mapstructure:"Salt"`
}

type encryptType int32

const (
	none encryptType = 0
	//request            encryptType = 1
	requestResponseVal encryptType = 2
)

// Connect to the loxone websocket
func New(host string, user string, password string) (WebsocketInterface, error) {

	// Check if all mandatory parameters were given
	if host == "" {
		return nil, errors.New("missing host")
	}
	if user == "" {
		return nil, errors.New("missing user")
	}
	if password == "" {
		return nil, errors.New("missing password")
	}

	loxone := &Loxone{
		Events:          make(chan *events.Event),
		host:            host,
		user:            user,
		password:        password,
		registerEvents:  false,
		callbackChannel: make(chan *websocketResponse),
		disconnected:    make(chan bool),
		stop:            make(chan bool),
		hooks:           make(map[string]func(*events.Event)),
		socketMessage:   make(chan *[]byte),
	}

	go loxone.handleMessages()

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

	// Handle disconnected
	go l.handleReconnect()

	return nil
}

func (l *Loxone) handleReconnect() {
	// If we finish, we restart a reconnect loop
	defer func() {
		log.Info("Stopping disconnect loop")
	}()

	for {
		select {
		case <-l.stop:
			break
		case <-l.disconnected:
			for {
				log.Warn("Disconnected, reconnecting in 30s")
				time.Sleep(30 * time.Second)

				err := l.connect()

				if err != nil {
					log.Warnf("Error during reconnection, retrying (%s)", err.Error())
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
}

func (l *Loxone) Close() {
	defer func() {
		l.socket.Close()
	}()

	close(l.stop)
	_ = l.socket.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
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

// AddHook ask the loxone server to send events
func (l *Loxone) AddHook(uuid string, callback func(*events.Event)) {
	l.hooks[uuid] = callback
}

func (l *Loxone) PumpEvents(stop <-chan bool) {
	go func() {
		for {
			select {
			case <-stop:
				log.Infof("Shutting Down")
				return
			case event := <-l.Events:
				if hook, ok := l.hooks[event.UUID]; ok {
					hook(event)
				}
				log.Debugf("event: %+v\n", event)
			}
		}
	}()
}

// GetConfig get the loxone server config
func (l *Loxone) GetConfig() (*Config, error) {
	config := &Config{}

	_, err := l.SendCommand(getConfig, config)

	if err != nil {
		return nil, err
	}

	return config, nil
}

// SendCommand Send a command to the loxone server
func (l *Loxone) SendCommand(cmd string, class interface{}) (*Body, error) {
	return l.sendCmdWithEnc(cmd, none, class)
}

func (l *Loxone) sendCmdWithEnc(cmd string, encryptType encryptType, class interface{}) (*Body, error) {
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
	return &Body{Code: 200}, nil
}

func (l *Loxone) sendSocketCmd(cmd *[]byte) (*websocketResponse, error) {
	log.Debug("Sending command to WS")
	err := l.socket.WriteMessage(websocket.TextMessage, *cmd)

	if err != nil {
		return nil, err
	}

	log.Debug("Waiting for answer")
	result := <-l.callbackChannel
	log.Debugf("WS answered")
	return result, nil
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
	resultValue := &SimpleValue{}
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

func (l *Loxone) createToken(user string, password string, uniqueID string) error {
	cmd := fmt.Sprintf(getUsersalt, user)

	salt := &salt{}
	_, err := l.sendCmdWithEnc(cmd, requestResponseVal, salt)

	if err != nil {
		return err
	}

	hash := l.encrypt.hashUser(user, password, salt.Salt, salt.OneTimeSalt)

	cmd = fmt.Sprintf(getToken, hash, user, 4, uniqueID, "GO")

	token := &token{}
	_, err = l.sendCmdWithEnc(cmd, requestResponseVal, token)

	if err != nil {
		return err
	}

	l.token = token
	return nil
}

func (l *Loxone) connectWs() error {
	log.Info("Connecting to WS")
	u := url.URL{Scheme: "ws", Host: l.host, Path: "/ws/rfc6455?_=" + strconv.FormatInt(time.Now().Unix(), 10)}

	socket, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	l.socket = socket
	if err != nil {
		return err
	}

	go l.readPump()

	return nil
}

func (l *Loxone) readPump() {
	defer func() {
		log.Info("Stopping websocket pump")
		defer l.socket.Close()
	}()
	log.Info("Starting websocket pump")

	for {
		_, message, err := l.socket.ReadMessage()
		if err != nil {
			l.disconnected <- true
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}

		log.Trace("Pushing new message from socket to socket channel")
		l.socketMessage <- &message
	}
}

func (l *Loxone) handleMessages() {
	incomingData := events.EmptyHeader
	var err error

	defer func() {
		log.Info("Stopping message handling")
	}()

	for {
		select {
		case <-l.stop:
			break
		case message := <-l.socketMessage:
			log.Trace("Sub new message from socket channel")

			// Check if we received an header or not
			if len(*message) == 8 {
				// we got an LX-Bin-header!
				incomingData, err = events.IdentifyHeader(*message)
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
						continue
					}

					if incomingData.EventType == events.EventTypeKeepalive {
						log.Debug("KeepAlive")
						incomingData = events.EmptyHeader
						continue
					}
					// Waiting for the data
					continue
				}

			} else if !incomingData.Empty && incomingData.Length == len(*message) {
				// Received message
				switch incomingData.EventType {
				case events.EventTypeText:
					log.Debug("Received a text message from previous header")
					l.callbackChannel <- &websocketResponse{data: message, responseType: incomingData.EventType}
				case events.EventTypeFile:
					log.Debug("Received a file from previous header")
					l.callbackChannel <- &websocketResponse{data: message, responseType: incomingData.EventType}
				case events.EventTypeEvent:
					l.handleBinaryEvent(message, incomingData.EventType)
				case events.EventTypeEventtext:
					l.handleBinaryEvent(message, incomingData.EventType)
				case events.EventTypeDaytimer:
					l.handleBinaryEvent(message, incomingData.EventType)
				case events.EventTypeWeather:
					l.handleBinaryEvent(message, incomingData.EventType)
				default:
					log.Warnf("Unknown event %d", incomingData.EventType)
				}

				incomingData = events.EmptyHeader
			} else {
				log.Debug("Received binary message without header")
				// TODO Send to error
			}
		}
	}
}

func (l *Loxone) handleBinaryEvent(binaryEvent *[]byte, eventType events.EventType) {
	events := events.InitBinaryEvent(binaryEvent, eventType)

	for _, event := range events.Events {
		l.Events <- event
	}
}

func (e *encrypt) hashUser(user string, password string, salt string, oneTimeSalt string) string {
	// create a SHA1 hash of the (salted) password
	hash := strings.ToUpper(crypto.Sha1Hash(fmt.Sprintf("%s:%s", password, salt)))

	// hash with user and otSalt
	return crypto.ComputeHmac256(fmt.Sprintf("%s:%s", user, hash), oneTimeSalt)
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

	publicKey := &SimpleValue{}
	_, err = deserializeLoxoneResponse(&body, publicKey)

	if err != nil {
		return nil, err
	}

	if publicKey.Value == "" {
		return nil, errors.New("pub key is empty")
	}

	return crypto.BytesToPublicKey(publicKey.Value)
}

func deserializeLoxoneResponse(jsonBytes *[]byte, class interface{}) (*Body, error) {
	raw := make(map[string]interface{})
	err := json.Unmarshal(*jsonBytes, &raw)
	if err != nil {
		return nil, err
	}

	ll := raw["LL"].(map[string]interface{})

	body := &Body{Control: ll["control"].(string)}

	var code interface{}
	// If can be on Code or code...
	if val, ok := ll["Code"]; ok {
		code = val
	}
	if val, ok := ll["code"]; ok {
		code = val
	}

	// Can be a string or a float...
	switch code := code.(type) {
	case string:
		i, _ := strconv.ParseInt(code, 10, 32)
		body.Code = int32(i)
	case float64:
		body.Code = int32(code)
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
