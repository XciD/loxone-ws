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
	"sync"
	"time"

	"github.com/XciD/loxone-ws/crypto"
	"github.com/XciD/loxone-ws/events"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/go-version"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
)

const (
	getApikey                    = "jdev/cfg/apiKey"
	getPublicKey                 = "jdev/sys/getPublicKey"
	keyExchange                  = "jdev/sys/keyexchange/%s"
	getUsersalt                  = "jdev/sys/getkey2/%s"
	getToken                     = "jdev/sys/gettoken/%s/%s/%d/%s/%s" // #nosec
	getJwt                       = "jdev/sys/getjwt/%s/%s/%d/%s/%s"   // #nosec
	authWithToken                = "authwithtoken/%s/%s"              // #nosec
	aesPayload                   = "salt/%s/%s"
	encryptionCmd                = "jdev/sys/enc/%s"
	encryptionCommandAndResponse = "jdev/sys/fenc/%s"
	registerEvents               = "jdev/sps/enablebinstatusupdate"
	getConfig                    = "data/LoxAPP3.json"
	MiniserverEpochOffset        = 1230768000
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

// ControlDetails details of a control
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
	autoReconnect     bool
	reconnectTimeout  time.Duration
	socketMu          sync.Mutex
	keepaliveInterval time.Duration
	connectionTimeout time.Duration

	// Miniserver capabilities
	httpsSupported bool // in jdev/cfg/apiKey response (httpsStatus: 1 Supported, 2 Supported but expired)
	useJwt         bool // 10.1.12.5
	useSHA256      bool // 10.4.0.0

}

// we only support token auth so assume min version 9.0.7.25 for this library

/*
TOKEN_CFG_VERSION: "8.4.5.10",
ENCRYPTION_CFG_VERSION: "8.1.10.14",
TOKENS: "9.0.7.25",
NON_TOKEN_AUTH_SUPPORTED: "9.3.0.0",
ENCRYPTED_SOCKET_CONNECTION: "7.4.4.1",
ENCRYPTED_CONNECTION_FULLY: "8.1.10.14",
ENCRYPTED_CONNECTION_HTTP_USER: "8.1.10.4",
TOKEN_REFRESH_AND_CHECK: "10.0.9.13",       // Tokens may now change when being refreshed. New webservice for checking token validity without changing them introduced
SECURE_HTTP_REQUESTS: "7.1.9.17",
JWT_SUPPORT: "10.1.12.5",                   // From this version onwards, JWTs are handled using separate commands to ensure regular apps remain unchanged.
SHA_256: "10.4.0.0"
*/

type LoxoneDownloadSocket interface {
	Close()
	GetFile(filename string) ([]byte, error)
}

type Loxone interface {
	GetEvents() <-chan events.Event
	Done() <-chan bool
	AddHook(uuid string, callback func(events.Event))
	SendCommand(command string, class interface{}) (*Body, error)
	SendEncryptedCommand(command string, class interface{}) (*Body, error)
	GetDownloadSocket() (LoxoneDownloadSocket, error)
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
	publicKey *rsa.PublicKey
	key       string
	iv        string
	timestamp time.Time
	salt      string
}

type token struct {
	Token        string
	Key          string
	ValidUntil   int64
	TokenRights  int32
	UnsecurePass bool
}

func (t *token) IsValid() bool {
	epoch := t.ValidUntil + MiniserverEpochOffset - 30 // 30 second buffer before expiration
	validTil := time.Unix(epoch, 0)
	return time.Now().Before(validTil)
}

// HashAlg defines the algorithm used to hash some user
// information during token generation
type HashAlg string

const (
	SHA1   HashAlg = "SHA1"
	SHA256 HashAlg = "SHA256"
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
	none               encryptType = 0
	request            encryptType = 1
	requestResponseVal encryptType = 2
)

// WebsocketOption is a type we use to customise our websocket, it enables dynamic configuration in an easy to use API
type WebsocketOption func(*websocketImpl) error

// WithAutoReconnect allows you to disable auto reconnect behaviour by passing this option with 'false'
func WithAutoReconnect(autoReconnect bool) WebsocketOption {
	return func(ws *websocketImpl) error {
		ws.autoReconnect = autoReconnect
		return nil
	}
}

// WithKeepAliveInterval allows you to set the interval where keepalive messages are sent,
// a duration of 0 disables keepalive. If not specified it will default to 2 seconds as per Loxone's own LxCommunicator.
func WithKeepAliveInterval(keepAliveInterval time.Duration) WebsocketOption {
	return func(ws *websocketImpl) error {
		ws.keepaliveInterval = keepAliveInterval
		return nil
	}
}

// WithConnectionTimeout allows you to set the connection timeout, the connection will close if nothing is
// received for this amount of time.
// If keepalive is enabled this will default to 3 * keepaliveTimeout, otherwise the connection will not timeout
// unless this option is specified. If keepalive is enabled this value must be higher than keepaliveInterval.
func WithConnectionTimeout(connectionTimeout time.Duration) WebsocketOption {
	return func(ws *websocketImpl) error {
		ws.connectionTimeout = connectionTimeout
		return nil
	}
}

// WithReconnectTimeout sets the time between disconnection and reconnect attempts
func WithReconnectTimeout(timeout time.Duration) WebsocketOption {
	return func(ws *websocketImpl) error {
		ws.reconnectTimeout = timeout
		return nil
	}
}

// WithRegisterEvents automatically registers for events upon connecting to the Miniserver
func WithRegisterEvents() WebsocketOption {
	return func(ws *websocketImpl) error {
		ws.registerEvents = true
		return nil
	}
}

// WithPort set a custom port for the Miniserver
func WithPort(port int) WebsocketOption {
	return func(ws *websocketImpl) error {
		ws.port = port
		return nil
	}
}

// WithUsernameAndPassword sets the username and password authentication, also used when supplied with a JWT
// to generate a new token if the provided token expires before being refreshed
func WithUsernameAndPassword(username string, password string) WebsocketOption {
	return func(ws *websocketImpl) error {
		if ws.user != "" && ws.user != username {
			return errors.New("the username you specified in WithUsernameAndPassword() doesn't match that of the token you provided")
		}
		ws.user = username
		ws.password = password
		return nil
	}
}

// WithJWTToken pre-sets the authentication token, at the moment there is no automatic refresh mechanism so it
// is safer to use alongside username and password authentication
func WithJWTToken(tokenString string) WebsocketOption {
	return func(ws *websocketImpl) error {

		jwtToken, err := jwt.Parse([]byte(tokenString))
		if err != nil {
			return err
		}

		loxoneToken := &token{
			Token: tokenString,
		}

		exp := jwtToken.Expiration()
		if !exp.IsZero() {
			loxoneToken.ValidUntil = exp.Unix() - MiniserverEpochOffset
		}

		if rights, exists := jwtToken.Get("tokenRights"); exists {
			if rightsInt, ok := rights.(int32); ok {
				loxoneToken.TokenRights = rightsInt
			}
		}

		if username, exists := jwtToken.Get("user"); exists {
			if username, ok := username.(string); ok {

				if ws.user != "" && ws.user != username {
					return errors.New("the username you specified in WithUsernameAndPassword() doesn't match that of the token you provided")
				}

				ws.user = username
			}
		}

		if ws.user == "" {
			return errors.New("could not infer the user from the token")
		}

		ws.token = loxoneToken

		return nil
	}
}

// New creates a websocket and connects to the Miniserver
func New(host string, opts ...WebsocketOption) (Loxone, error) {

	// Check if all mandatory parameters were given
	if host == "" {
		return nil, errors.New("missing host")
	}

	loxone := &websocketImpl{
		Events:            make(chan events.Event),
		host:              host,
		port:              80,
		registerEvents:    false,
		callbackChannel:   make(chan *websocketResponse),
		disconnected:      make(chan bool),
		stop:              make(chan bool),
		hooks:             make(map[string]func(events.Event)),
		socketMessage:     make(chan []byte),
		autoReconnect:     true,
		reconnectTimeout:  30 * time.Second,
		useJwt:            true,
		useSHA256:         true,
		keepaliveInterval: 2 * time.Second, // seems like a small number but Loxone's own LxCommunicator uses this value
	}

	// Loop through each option
	for _, opt := range opts {
		err := opt(loxone)
		if err != nil {
			return nil, err
		}
	}

	if loxone.keepaliveInterval > 0 && loxone.connectionTimeout == 0 {
		loxone.connectionTimeout = 3 * loxone.keepaliveInterval
	}

	if loxone.connectionTimeout < loxone.keepaliveInterval {
		return nil, errors.New("you cannot have a connection timeout less than the keepalive interval")
	}

	if loxone.token == nil && (loxone.user == "" || loxone.password == "") {
		return nil, errors.New("you must specify at least one of WithUsernameAndPassword() or WithJWTToken() options")
	}

	go loxone.handleMessages()

	err := loxone.connect()

	if err != nil {
		return nil, err
	}

	return loxone, nil
}

func (l *websocketImpl) GetDownloadSocket() (LoxoneDownloadSocket, error) {
	// clone current socket but with no keepalive or timeout
	downloadSocket := &websocketImpl{
		Events:          make(chan events.Event),
		host:            l.host,
		port:            l.port,
		callbackChannel: make(chan *websocketResponse),
		disconnected:    make(chan bool),
		stop:            make(chan bool),
		socketMessage:   make(chan []byte),
		useJwt:          true,
		useSHA256:       true,
		user:            l.user,
		password:        l.password,
		token:           l.token,
	}

	go downloadSocket.handleMessages()

	err := downloadSocket.connect()

	if err != nil {
		return nil, err
	}

	return downloadSocket, nil
}

func (l *websocketImpl) connect() error {

	// this is recommended to be done first by docs, gives MS version and HTTPS status
	log.Info("Asking for API Key, Version, and HTTPS Status ")
	err := l.getMiniserverCapabilities()
	if err != nil {
		return err
	}

	err = l.connectWs()

	if err != nil {
		return err
	}

	err = l.authenticate()

	if err != nil {
		// if auth fails on a reconnect, there's no point in trying any more, assume password changed?
		return err
	}

	if l.registerEvents {
		// handle this error?
		_ = l.RegisterEvents()
	}

	// Handle disconnected
	go l.handleReconnect()

	return nil
}

func (l *websocketImpl) handleReconnect() {
	// If we finish, we restart a reconnect loop

	// init a timer we may not need, but need the channel to be valid
	keepAliveTimer := time.NewTimer(0)
	<-keepAliveTimer.C

	defer func() {
		keepAliveTimer.Stop()
		log.Info("Stopping disconnect loop")
	}()

	log.Info("Starting disconnect loop")

	for {

		if l.keepaliveInterval > 0 {
			keepAliveTimer.Reset(l.keepaliveInterval)
		}

		select {
		case <-l.stop:
			return
		case <-l.disconnected:

			// if auto reconnect is disabled, close the stop channel and return immediately
			if !l.autoReconnect {
				close(l.stop)
				return
			}

			for {
				log.Warnf("Disconnected, reconnecting in %s", l.reconnectTimeout)

				// check for stop during reconnect loop
				select {
				case <-l.stop:
					return
				case <-time.After(l.reconnectTimeout):
					err := l.connect()

					if err != nil {
						log.Warnf("Error during reconnection, retrying (%s)", err.Error())
						continue
					}

					return
				}
			}
		case <-keepAliveTimer.C:
			log.Trace("Sending keepalive")
			_ = l.write(websocket.TextMessage, []byte("keepalive"))
		}
	}

}

// Close closes the connection to the Miniserver
func (l *websocketImpl) Close() {
	close(l.stop)
	_ = l.write(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	_ = l.socket.Close()
}

func (l *websocketImpl) write(messageType int, data []byte) error {
	// as per https://pkg.go.dev/github.com/gorilla/websocket#hdr-Concurrency ensuring one concurrent write
	// another option is to set up a write pump, we can't assume user isn't using goroutines to issue commands
	l.socketMu.Lock()
	defer l.socketMu.Unlock()
	return l.socket.WriteMessage(messageType, data)
}

// RegisterEvents ask the Miniserver to send events
func (l *websocketImpl) RegisterEvents() error {
	l.registerEvents = true

	_, err := l.SendCommand(registerEvents, nil)

	if err != nil {
		return err
	}

	return nil
}

// AddHook add a hook for a specific control, assumed at most one hook per uuid
func (l *websocketImpl) AddHook(uuid string, callback func(events.Event)) {
	l.hooks[uuid] = callback
}

// GetEvents returns the events in a receive only channel
func (l *websocketImpl) GetEvents() <-chan events.Event {
	return l.Events
}

func (l *websocketImpl) Done() <-chan bool {
	return l.stop
}

// PumpEvents starts processing events to trigger registered hooks
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

// GetConfig get the Miniserver config
func (l *websocketImpl) GetConfig() (*Config, error) {
	config := &Config{}

	_, err := l.SendCommand(getConfig, config)

	if err != nil {
		return nil, err
	}

	return config, nil
}

func (l *websocketImpl) GetFile(filename string) ([]byte, error) {
	// TODO open up a second socket for this to not block events
	bytes := []byte(filename)
	res, err := l.sendSocketCmd(&bytes)
	if err != nil {
		return nil, err
	}
	if res.responseType != events.EventTypeFile {
		return nil, errors.New("request is not a binary file or it doesn't exist")
	}
	return res.data, nil
}

// SendCommand Send an unencrypted command to the Miniserver
func (l *websocketImpl) SendCommand(cmd string, class interface{}) (*Body, error) {
	return l.sendCmdWithEnc(cmd, none, class)
}

// SendEncryptedCommand Send an encrypted command to the Miniserver
func (l *websocketImpl) SendEncryptedCommand(cmd string, class interface{}) (*Body, error) {
	return l.sendCmdWithEnc(cmd, requestResponseVal, class)
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

	if err := l.write(websocket.TextMessage, *cmd); err != nil {
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
	publicKey, err := l.getPublicKeyFromServer()

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

	oneTimeSalt, err := crypto.DecryptAES(resultValue.Value, uniqueID, ivKey)

	if err != nil {
		return err
	}

	l.encrypt = &encrypt{
		publicKey: publicKey,
		key:       uniqueID,
		iv:        ivKey,
		timestamp: time.Now(),
		salt:      crypto.CreateEncryptKey(2),
	}

	log.Info("Key Exchange OK")
	log.Info("Authentication Starting")

	if l.token != nil && l.token.IsValid() {
		log.Debug("Token still valid, can attempt to re-use")

		// TODO: check token really is valid

		if err := l.reuseToken(string(oneTimeSalt)); err != nil {
			return err
		}

		log.Info("Authentication OK with existing token")
		return nil
	}

	err = l.createToken()
	if err != nil {
		return err
	}

	log.Info("Authentication OK with new token")

	return nil
}

func (l *websocketImpl) reuseToken(oneTimeSalt string) error {

	if oneTimeSalt == "" {
		key := &SimpleValue{}
		_, err := l.sendCmdWithEnc("jdev/sys/getkey", requestResponseVal, key)
		if err != nil {
			return err
		}
		oneTimeSalt = key.Value
	}

	var alg HashAlg
	if l.useSHA256 {
		alg = SHA256
	} else {
		alg = SHA1
	}

	hash := l.encrypt.hashToken(l.token.Token, oneTimeSalt, alg)

	cmd := fmt.Sprintf(authWithToken, hash, l.user)

	token := &token{}
	_, err := l.sendCmdWithEnc(cmd, requestResponseVal, token)
	if err != nil {
		return err
	}

	// updating token values
	l.token.TokenRights = token.TokenRights
	l.token.ValidUntil = token.ValidUntil
	l.token.UnsecurePass = token.UnsecurePass

	return nil
}

func (l *websocketImpl) getSalt() (*salt, error) {
	cmd := fmt.Sprintf(getUsersalt, l.user)

	salt := &salt{}
	_, err := l.sendCmdWithEnc(cmd, requestResponseVal, salt)

	if err != nil {
		return nil, err
	}

	if !salt.HashAlgorithm.Valid() {
		return nil, fmt.Errorf("unsupported hash algorithm given. For now only '%s' and '%s' are supported", SHA1, SHA256)
	}

	return salt, nil
}

func (l *websocketImpl) createToken() error {

	salt, err := l.getSalt()
	if err != nil {
		return err
	}

	hash := l.encrypt.hashUser(l.user, l.password, salt.Salt, salt.OneTimeSalt, salt.HashAlgorithm)

	var cmd string
	if l.useJwt {
		cmd = fmt.Sprintf(getJwt, hash, l.user, 4, l.encrypt.key, "GO")
	} else {
		cmd = fmt.Sprintf(getToken, hash, l.user, 4, l.encrypt.key, "GO")
	}

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
		_ = l.socket.Close()
	}()
	log.Info("Starting websocket pump")

	for {

		// double check to make sure the socket hasn't got stuck
		// had some (rare) examples where closing socket didn't break this loop
		select {
		case <-l.stop:
			return
		default:
		}

		if l.connectionTimeout > 0 {
			_ = l.socket.SetReadDeadline(time.Now().Add(l.connectionTimeout))
		}
		_, message, err := l.socket.ReadMessage()

		if err != nil {

			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}

			// if Close called we don't want to send to a potentially blocked channel
			select {
			case <-l.stop:
				return
			default:
			}
			l.disconnected <- true

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
	e := events.InitBinaryEvent(binaryEvent, eventType)

	for _, event := range e.Events {
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
		return crypto.ComputeHmac1(fmt.Sprintf("%s:%s", user, hash), oneTimeSalt)
	case SHA256:
		hash = strings.ToUpper(crypto.Sha256Hash(passwordSalt))
		return crypto.ComputeHmac256(fmt.Sprintf("%s:%s", user, hash), oneTimeSalt)
	}

	// hash with user and otSalt
	return ""
}

func (e *encrypt) hashToken(token string, oneTimeSalt string, alg HashAlg) string {

	switch alg {
	case SHA1:
		return crypto.ComputeHmac1(token, oneTimeSalt)
	case SHA256:
		return crypto.ComputeHmac256(token, oneTimeSalt)
	}

	return ""
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

type apiKeyResponse struct {
	Snr         string
	Version     string
	Key         string
	HttpsStatus int32
}

func (l *websocketImpl) getMiniserverCapabilities() error {

	client := &http.Client{}
	client.Timeout = 5 * time.Second
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:%d/%s", l.host, l.port, getApikey), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)

	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	apiKeyValue := &SimpleValue{}
	_, err = deserializeLoxoneResponse(body, apiKeyValue)

	if err != nil {
		return err
	}

	if apiKeyValue.Value == "" {
		return errors.New("api key response from Miniserver is empty")
	}

	apiKeyValue.Value = strings.ReplaceAll(apiKeyValue.Value, "'", "\"")

	apiKey := &apiKeyResponse{}
	err = json.Unmarshal([]byte(apiKeyValue.Value), apiKey)

	if err != nil {
		return err
	}

	// Making an assumption based on the fact that if anything errors it will most likely be the absolute
	// latest version and support the latest features as this has been tested with older firmwares

	if miniserverVersion, err := version.NewVersion(apiKey.Version); err == nil {
		if jwtVersion, err := version.NewVersion("10.1.12.5"); err == nil && miniserverVersion.LessThan(jwtVersion) {
			l.useJwt = false
		}
		if sha256Version, err := version.NewVersion("10.4.0.0"); err == nil && miniserverVersion.LessThan(sha256Version) {
			l.useSHA256 = false
		}
	}

	return nil
}

func (l *websocketImpl) getPublicKeyFromServer() (*rsa.PublicKey, error) {
	client := &http.Client{}
	client.Timeout = 5 * time.Second

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:%d/%s", l.host, l.port, getPublicKey), nil)
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

func deserializeLoxoneResponse(jsonBytes []byte, class interface{}) (body *Body, err error) {

	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprintf("failed to deserialize Miniserver response in to the provided struct, %s", r))
		}
	}()

	raw := make(map[string]interface{})
	err = json.Unmarshal(jsonBytes, &raw)
	if err != nil {
		return
	}

	ll := raw["LL"].(map[string]interface{})

	body = &Body{Control: ll["control"].(string)}

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
		err = mapstructure.Decode(ll["value"], &class)
		if err != nil {
			return
		}
	}

	return
}
