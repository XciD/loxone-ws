package types

type Type string

const (
	Switch            Type = "Switch"
	LeftRightAnalog   Type = "LeftRightAnalog"
	InfoOnlyDigital   Type = "InfoOnlyDigital"
	CentralJalousie   Type = "CentralJalousie"
	InfoOnlyAnalog    Type = "InfoOnlyAnalog"
	IRCDaytimer       Type = "IRCDaytimer"
	Jalousie          Type = "Jalousie"
	AlarmClock        Type = "AlarmClock"
	Daytimer          Type = "Daytimer"
	Presence          Type = "Presence"
	LightControllerV2 Type = "LightControllerV2"
	Dimmer            Type = "Dimmer"
	ColorPickerV2     Type = "ColorPickerV2"
	IRoomController   Type = "IRoomController"
	Meter             Type = "Meter"
	UpDownDigital     Type = "UpDownDigital"
	SmokeAlarm        Type = "SmokeAlarm"
	TextState         Type = "TextState"
	Intercom          Type = "Intercom"
	Alarm             Type = "Alarm"
	Gate              Type = "Gate"
	UpDownAnalog      Type = "UpDownAnalog"
	Pushbutton        Type = "Pushbutton"
	WindowMonitor     Type = "WindowMonitor"
	EIBDimmer         Type = "EIBDimmer"
	CentralAlarm      Type = "CentralAlarm"
	Hourcounter       Type = "Hourcounter"
	Tracker           Type = "Tracker"
)
