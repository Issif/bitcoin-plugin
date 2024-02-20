package main

import (
	bitcoin "github.com/Issif/bitcoin-plugin/pkg"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	ID          uint32 = 16
	Name               = "bitcoin"
	Description        = "bitcoin Events"
	Contact            = "github.com/falcosecurity/plugins/"
	Version            = "0.1.0"
	EventSource        = "bitcoin"
)

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &bitcoin.Plugin{}
		p.SetInfo(
			ID,
			Name,
			Description,
			Contact,
			Version,
			EventSource,
		)
		extractor.Register(p)
		source.Register(p)
		return p
	})
}

func main() {}
