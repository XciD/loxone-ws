package loxonews

import (
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type loxoneWebsocket struct {
	host            string
	url             url.URL
	socket          *websocket.Conn
	internalCmdChan chan *websocketResponse
	events          chan *Event
	disconnect      chan bool
}

type websocketResponse struct {
	data         *[]byte
	responseType eventType
}

func createSocket(host string) *loxoneWebsocket {
	u := url.URL{Scheme: "ws", Host: host, Path: "/ws/rfc6455?_=" + strconv.FormatInt(time.Now().Unix(), 10)}
	log.Infof("connecting to %s", host)

	return &loxoneWebsocket{
		host:            host,
		url:             u,
		internalCmdChan: make(chan *websocketResponse),
		disconnect:      make(chan bool),
	}
}

func (s *loxoneWebsocket) connect(events chan *Event) error {
	socket, _, err := websocket.DefaultDialer.Dial(s.url.String(), nil)
	s.socket = socket
	if err != nil {
		return err
	}

	s.events = events

	go s.listen()

	return nil
}

func (s *loxoneWebsocket) listen() {
	defer s.close()

	incomingData := emptyHeader

	for {
		_, message, err := s.socket.ReadMessage()
		if err != nil {
			log.Error("read error:", err)
			s.disconnect <- true
			return
		}
		// Check if we received an header or not
		if len(message) == 8 {
			// we got an LX-Bin-header!
			incomingData, err = identifyHeader(message)
			if err != nil {
				log.Debugf("Error during identify header %v", err)
				incomingData = emptyHeader
			} else if incomingData.length == 0 && incomingData.eventType != outofservice && incomingData.eventType != keepalive {
				log.Debug("received header telling 0 bytes payload - resolve request with null!")
				// TODO sendOnBinaryMessage
				incomingData = emptyHeader
			} else {
				log.Debugf("Received header: %+v\n", incomingData)

				if incomingData.eventType == outofservice {
					log.Warn("Miniserver out of service!")
					incomingData = emptyHeader
					s.disconnect <- true
					break
				}

				if incomingData.eventType == keepalive {
					log.Debug("KeepAlive")
					incomingData = emptyHeader
					continue
				}
				// Waiting for the data
				continue
			}

		} else if !incomingData.empty && incomingData.length == len(message) {
			// Received message
			switch incomingData.eventType {
			case text:
				log.Debug("Received a text message from previous header")
				s.internalCmdChan <- &websocketResponse{data: &message, responseType: incomingData.eventType}
			case file:
				log.Debug("Received a file from previous header")
				s.internalCmdChan <- &websocketResponse{data: &message, responseType: incomingData.eventType}
			case event:
				s.handleBinaryEvent(&message, incomingData.eventType)
			case eventtext:
				s.handleBinaryEvent(&message, incomingData.eventType)
			case daytimer:
				s.handleBinaryEvent(&message, incomingData.eventType)
			case weather:
				s.handleBinaryEvent(&message, incomingData.eventType)
			default:
				log.Warnf("Unknown event %d", incomingData.eventType)
			}

			incomingData = emptyHeader
		} else {
			log.Debug("Received binary message without header ")
			// TODO Send to error
		}
	}
}

func (s *loxoneWebsocket) handleBinaryEvent(binaryEvent *[]byte, eventType eventType) {
	events := initBinaryEvent(binaryEvent, eventType)

	for _, event := range events.events {
		s.events <- event
	}
}

func (s *loxoneWebsocket) close() {
	log.Warn("Closing Socket")
	defer s.socket.Close()
	err := s.socket.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		log.Println("write close:", err)
		return
	}
}

func (s *loxoneWebsocket) sendCmd(cmd *[]byte) (*websocketResponse, error) {
	log.Debug("Sending commande to WS")
	err := s.socket.WriteMessage(websocket.TextMessage, *cmd)

	if err != nil {
		return nil, err
	}

	log.Debug("Waiting for answer")
	result := <-s.internalCmdChan
	log.Debugf("WS answered")
	return result, nil
}
