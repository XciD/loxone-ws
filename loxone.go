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
	"sync/atomic"
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
	Name        string
	Type        string
	UUIDAction  string
	IsFavorite  bool `json:"isFavorite"`
	Room        string
	Cat         string
	States      map[string]interface{} // Can be an array or a string
	Details     ControlDetails
	Statistic   ControlStatistic
	SubControls map[string]*Control
}

// StatisticalNames returns a list of names for the given control and
// the statistical data the control writes. first we will loop over the
// outputs values within the statistics of the control, trying to find
// a state with a matching uuid. If no entry was found, we will use the
// name of the statistic entry in the output array.
func (cntl *Control) StatisticalNames() []string {
	names := make([]string, 0)
	// loop over the statistic outputs
	for _, output := range cntl.Statistic.Outputs {
		var name string
		// loop over the states
		for key, state := range cntl.States {
			// now get the name of the state
			// which matches and set it as name
			if state == output.UUID {
				name = key
				break
			}
		}

		// if the name wasn't found, use the
		// name of the output from the statistic
		if name == "" {
			name = output.Name
		}

		// append the name
		names = append(names, name)
	}

	return names
}

type ControlStatistic struct {
	Frequency int                    `json:"frequency"`
	Outputs   []ControlStatisticItem `json:"outputs"`
}

type ControlStatisticItem struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Format   string `json:"format"`
	UUID     string `json:"uuid"`
	VisuType int    `json:"visuType"`
}

// GetControl returns the control with the given uuid
func (cfg *Config) GetControl(uuid string) *Control {
	for key, control := range cfg.Controls {
		if key == uuid {
			return control
		}
	}
	return nil
}

// Details of a control
type ControlDetails struct {
	Format string
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
type websocketImpl struct {
	host              string
	port              int
	user              string
	password          string
	encrypt           *encrypt
	token             *token
	Events            chan events.Event
	callbackChannel   chan *websocketResponse
	socketMessage     chan []byte
	socket            *websocket.Conn
	disconnected      chan bool
	stop              chan bool
	hooks             map[string]func(events.Event)
	registerEvents    bool
	reconnectHandlers int32
}

type Loxone interface {
	GetEvents() chan events.Event
	AddHook(uuid string, callback func(events.Event))
	SendCommand(command string, class interface{}) (*Body, error)
	Close()
	RegisterEvents() error
	PumpEvents(stop <-chan bool)
	GetConfig() (*Config, error)
}

type websocketResponse struct {
	data         []byte
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

// HashAlg defines the algorithm used to hash some user
// information during token generation
type HashAlg string

const (
	SHA1   = "SHA1"
	SHA256 = "SHA256"
)

// Valid checks for valid & supported hash algorithms. The
// value for the algorithm is returned by the miniserver within
// the process of getting an auth-token and will be used for
// hashing {password}:{userSalt} and {user}:{pwHash} within
// createToken() / hashUser()
func (ha HashAlg) Valid() bool {
	return (ha == SHA1 || ha == SHA256) && len(ha) > 0
}

type salt struct {
	OneTimeSalt   string  `mapstructure:"key"`
	Salt          string  `mapstructure:"Salt"`
	HashAlgorithm HashAlg `mapstructure:"hashAlg"`
}

type encryptType int32

const (
	none encryptType = 0
	// request            encryptType = 1
	requestResponseVal encryptType = 2
)

// Connect to the loxone websocket
func New(host string, port int, user string, password string) (Loxone, error) {

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

	loxone := &websocketImpl{
		Events:            make(chan events.Event),
		host:              host,
		port:              port,
		user:              user,
		password:          password,
		registerEvents:    false,
		callbackChannel:   make(chan *websocketResponse),
		disconnected:      make(chan bool),
		stop:              make(chan bool),
		hooks:             make(map[string]func(events.Event)),
		socketMessage:     make(chan []byte),
		reconnectHandlers: 0,
	}

	go loxone.handleMessages()

	err := loxone.connect()

	if err != nil {
		return nil, err
	}

	return loxone, nil
}

func (l *websocketImpl) connect() error {
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

func (l *websocketImpl) handleReconnect() {
	// If we finish, we restart a reconnect loop
	defer func() {
		atomic.AddInt32(&l.reconnectHandlers, -1)
		log.Info("Stopping disconnect loop")
	}()

	atomic.AddInt32(&l.reconnectHandlers, 1)

	for {
		select {
		case <-l.stop:
			return
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
			return
		}
	}

}

func (l *websocketImpl) Close() {
	defer func() {
		l.socket.Close()
	}()

	close(l.stop)
	_ = l.socket.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

// RegisterEvents ask the loxone server to send events
func (l *websocketImpl) RegisterEvents() error {
	l.registerEvents = true

	_, err := l.SendCommand(registerEvents, nil)

	if err != nil {
		return err
	}

	return nil
}

// AddHook ask the loxone server to send events
func (l *websocketImpl) AddHook(uuid string, callback func(events.Event)) {
	l.hooks[uuid] = callback
}

func (l *websocketImpl) GetEvents() chan events.Event {
	return l.Events
}

func (l *websocketImpl) PumpEvents(stop <-chan bool) {
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
func (l *websocketImpl) GetConfig() (*Config, error) {
	config := &Config{}

	_, err := l.SendCommand(getConfig, config)

	if err != nil {
		return nil, err
	}

	return config, nil
}

// SendCommand Send a command to the loxone server
func (l *websocketImpl) SendCommand(cmd string, class interface{}) (*Body, error) {
	return l.sendCmdWithEnc(cmd, none, class)
}

func (l *websocketImpl) sendCmdWithEnc(cmd string, encryptType encryptType, class interface{}) (*Body, error) {
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
		decryptedResult, err := l.encrypt.decryptCmd(result.data)
		if err != nil {
			return nil, err
		}
		result.data = decryptedResult
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
			err := json.Unmarshal(result.data, &class)
			if err != nil {
				return nil, err
			}
			// Response is copied to class
			return nil, nil
		}
		return nil, fmt.Errorf("unHandled response type: %d", result.responseType)
	}

	log.Debug(string(result.data))
	return &Body{Code: 200}, nil
}

func (l *websocketImpl) sendSocketCmd(cmd *[]byte) (*websocketResponse, error) {
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

func (l *websocketImpl) authenticate() error {
	// Retrieve public key
	log.Info("Asking for Public Key")
	publicKey, err := getPublicKeyFromServer(l.host, l.port)

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

func (l *websocketImpl) createToken(user string, password string, uniqueID string) error {
	cmd := fmt.Sprintf(getUsersalt, user)

	salt := &salt{}
	_, err := l.sendCmdWithEnc(cmd, requestResponseVal, salt)

	if err != nil {
		return err
	}

	if !salt.HashAlgorithm.Valid() {
		return fmt.Errorf("unsupported hash algorithm given. For now only '%s' and '%s' are supported", SHA1, SHA256)
	}

	hash := l.encrypt.hashUser(user, password, salt.Salt, salt.OneTimeSalt, salt.HashAlgorithm)

	cmd = fmt.Sprintf(getToken, hash, user, 4, uniqueID, "GO")

	token := &token{}
	_, err = l.sendCmdWithEnc(cmd, requestResponseVal, token)

	if err != nil {
		return err
	}

	l.token = token
	return nil
}

func (l *websocketImpl) connectWs() error {
	log.Info("Connecting to WS")
	u := url.URL{Scheme: "ws", Host: fmt.Sprintf("%s:%d", l.host, l.port), Path: "/ws/rfc6455?_=" + strconv.FormatInt(time.Now().Unix(), 10)}

	socket, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	l.socket = socket
	if err != nil {
		return err
	}

	go l.readPump()

	return nil
}

func (l *websocketImpl) readPump() {
	defer func() {
		log.Info("Stopping websocket pump")
		defer l.socket.Close()
	}()
	log.Info("Starting websocket pump")

	for {
		_, message, err := l.socket.ReadMessage()
		if err != nil {
			// using atomic instead of buffered channel in case we allow disabling auto reconnect in the future
			if handlers := atomic.LoadInt32(&l.reconnectHandlers); handlers > 0 {
				l.disconnected <- true
			}
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}

		log.Trace("Pushing new message from socket to socket channel")
		l.socketMessage <- message
	}
}

func (l *websocketImpl) handleMessages() {
	incomingData := events.EmptyHeader
	var err error

	defer func() {
		log.Info("Stopping message handling")
	}()

	for {
		select {
		case <-l.stop:
			return
		case message := <-l.socketMessage:
			log.Trace("Sub new message from socket channel")

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

			} else if !incomingData.Empty && incomingData.Length == len(message) {
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

func (l *websocketImpl) handleBinaryEvent(binaryEvent []byte, eventType events.EventType) {
	events := events.InitBinaryEvent(binaryEvent, eventType)

	for _, event := range events.Events {
		l.Events <- event
	}
}

func (e *encrypt) hashUser(user string, password string, salt string, oneTimeSalt string, hashAlg HashAlg) string {
	//
	var hash string
	passwordSalt := fmt.Sprintf("%s:%s", password, salt)

	// create a SHA1/SHA256 hash of the (salted) password
	switch hashAlg {
	case SHA1:
		hash = strings.ToUpper(crypto.Sha1Hash(passwordSalt))
		break
	case SHA256:
		hash = strings.ToUpper(crypto.Sha256Hash(passwordSalt))
		break
	}

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

func getPublicKeyFromServer(url string, port int) (*rsa.PublicKey, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:%d/%s", url, port, getPublicKey), nil)
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
	_, err = deserializeLoxoneResponse(body, publicKey)

	if err != nil {
		return nil, err
	}

	if publicKey.Value == "" {
		return nil, errors.New("pub key is empty")
	}

	return crypto.BytesToPublicKey(publicKey.Value)
}

func deserializeLoxoneResponse(jsonBytes []byte, class interface{}) (*Body, error) {
	raw := make(map[string]interface{})
	err := json.Unmarshal(jsonBytes, &raw)
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
