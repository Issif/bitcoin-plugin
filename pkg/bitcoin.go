package bitcoin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/gorilla/websocket"
)

var (
	ID          uint32
	Name        string
	Description string
	Contact     string
	Version     string
	EventSource string
)

type PluginConfig struct {
}

// Plugin represents our plugin
type Plugin struct {
	plugins.BasePlugin
	Config          PluginConfig
	lastBTCEvent    Event
	lastBTCEventNum uint64
}

type Tx struct {
	Op string `json:"op"`
	X  struct {
		Time      int64  `json:"time"`
		Hash      string `json:"hash"`
		Relayedby string `json:"relayed_by"`
		Inputs    []struct {
			PrevOut struct {
				Spent bool   `json:"spent"`
				Addr  string `json:"addr"`
				Value int64  `json:"value"`
			} `json:"prev_out"`
		} `json:"inputs"`
		Out []struct {
			Spent bool   `json:"spent"`
			Addr  string `json:"addr"`
			Value int64  `json:"value"`
		} `json:"out"`
	} `json:"x"`
}

type Event struct {
	Time         int64    `json:"time"`
	Hash         string   `json:"hash"`
	Wallet       string   `json:"wallet"`
	Relayedby    string   `json:"relayed_by"`
	Amount       uint64   `json:"amount"`
	Transaction  string   `json:"transaction"`
	Destinations []string `json:"destinations"`
	Sources      []string `json:"sources"`
}

// SetInfo is used to set the Info of the plugin
func (p *Plugin) SetInfo(id uint32, name, description, contact, version, eventSource string) {
	ID = id
	Name = name
	Contact = contact
	Version = version
	EventSource = eventSource
}

// Info displays information of the plugin to Falco plugin framework
func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          ID,
		Name:        Name,
		Description: Description,
		Contact:     Contact,
		Version:     Version,
		EventSource: EventSource,
	}
}

// Init is called by the Falco plugin framework as first entry,
// we use it for setting default configuration values and mapping
// values from `init_config` (json format for this plugin)
func (p *Plugin) Init(config string) error {
	return nil
}

// Fields exposes to Falco plugin framework all availables fields for this plugin
func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "uint64", Name: "btc.time", Desc: "Time"},
		{Type: "string", Name: "btc.wallet", Desc: "Wallet"},
		{Type: "string", Name: "btc.hash", Desc: "Hash"},
		{Type: "string", Name: "btc.relayedby", Desc: "Relayed by"},
		{Type: "string", Name: "btc.amount", Desc: "Amount in BTC"},
		{Type: "string", Name: "btc.transaction", Desc: "Transaction"},
		{Type: "string", Name: "btc.destinations", Desc: "Destinations", IsList: true, Arg: sdk.FieldEntryArg{IsIndex: true}},
		{Type: "string", Name: "btc.sources", Desc: "Sources", IsList: true, Arg: sdk.FieldEntryArg{IsIndex: true}},
	}
}

// Extract allows Falco plugin framework to get values for all available fields
func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	btc := p.lastBTCEvent

	// For avoiding to Unmarshal the same message for each field to extract
	// we store it with its EventNum. When it's a new event with a new message, we
	// update the Plugin struct.
	if evt.EventNum() != p.lastBTCEventNum {
		rawData, err := io.ReadAll(evt.Reader())
		if err != nil {
			return err
		}

		err = json.Unmarshal(rawData, &btc)
		if err != nil {
			return err
		}

		p.lastBTCEvent = btc
		p.lastBTCEventNum = evt.EventNum()
	}

	switch req.Field() {
	case "btc.time":
		req.SetValue(btc.Time)
	case "btc.wallet":
		req.SetValue(btc.Wallet)
	case "btc.hash":
		req.SetValue(btc.Hash)
	case "btc.relaydby":
		req.SetValue(btc.Relayedby)
	case "btc.amount":
		f := float64(btc.Amount) / 1000000000
		req.SetValue(fmt.Sprintf("%.9f", f))
	case "btc.transaction":
		req.SetValue(btc.Transaction)
	case "btc.destinations":
		req.SetValue(btc.Destinations)
	case "btc.sources":
		req.SetValue(btc.Sources)
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}

// Open is called by Falco plugin framework for opening a stream of events, we call that an instance
func (Plugin *Plugin) Open(params string) (source.Instance, error) {
	eventC := make(chan source.PushEvent)

	// launch an async worker that listens for bitcoin tx and pushes them
	// to the event channel
	go func() {
		defer close(eventC)

		u := url.URL{Scheme: "wss", Host: "ws.blockchain.info", Path: "inv"}
		v, _ := url.QueryUnescape(u.String())

		wsChan, _, err := websocket.DefaultDialer.Dial(v, make(http.Header))
		if err != nil {
			eventC <- source.PushEvent{Err: err}
			return
		}
		defer wsChan.Close()

		err = wsChan.WriteMessage(websocket.TextMessage, []byte(`{"op": "unconfirmed_sub"}`))
		if err != nil {
			eventC <- source.PushEvent{Err: err}
			return
		}

		for {
			_, msg, err := wsChan.ReadMessage()
			if err != nil {
				eventC <- source.PushEvent{Err: err}
				return
			}
			var tx Tx
			err = json.Unmarshal(msg, &tx)
			if err != nil {
				eventC <- source.PushEvent{Err: err}
				return
			}
			for _, i := range tx.X.Inputs {
				var d []string
				for _, j := range tx.X.Out {
					d = append(d, j.Addr)
				}
				event := Event{
					Time:         tx.X.Time,
					Hash:         tx.X.Hash,
					Relayedby:    tx.X.Relayedby,
					Wallet:       i.PrevOut.Addr,
					Amount:       uint64(i.PrevOut.Value),
					Transaction:  "sent",
					Destinations: d,
				}
				m, _ := json.Marshal(event)
				eventC <- source.PushEvent{Data: m}
			}
			for _, i := range tx.X.Out {
				var d []string
				for _, j := range tx.X.Inputs {
					d = append(d, j.PrevOut.Addr)
				}
				event := Event{
					Time:        tx.X.Time,
					Hash:        tx.X.Hash,
					Relayedby:   tx.X.Relayedby,
					Wallet:      i.Addr,
					Amount:      uint64(i.Value),
					Transaction: "received",
					Sources:     d,
				}
				fmt.Println(d)
				m, _ := json.Marshal(event)
				eventC <- source.PushEvent{Data: m}
			}

		}
	}()
	return source.NewPushInstance(eventC)
}

// String represents the raw value of on event
// (not currently used by Falco plugin framework, only there for future usage)
func (Plugin *Plugin) String(in io.ReadSeeker) (string, error) {
	evtBytes, err := io.ReadAll(in)
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)
	return fmt.Sprintf("%v", evtStr), nil
}
