package main

import (
	"fmt"
	"net"

	"github.com/df-mc/go-nethernet"
	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
	"github.com/sandertv/gophertunnel/minecraft"
)

// loopbackNetwork keeps media on the same loopback interface as the local probe.
// The caller closes the returned socket owner after closing its listener.
func loopbackNetwork() (minecraft.NetherNet, func() error, error) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return minecraft.NetherNet{}, nil, fmt.Errorf("listen for loopback media: %w", err)
	}
	mux := webrtc.NewICEUDPMux(nil, conn)
	var settings webrtc.SettingEngine
	settings.SetIncludeLoopbackCandidate(true)
	settings.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	settings.SetICEUDPMux(mux)
	network := minecraft.NetherNet{
		ListenConfig: nethernet.ListenConfig{
			API: webrtc.NewAPI(webrtc.WithSettingEngine(settings)),
		},
	}
	return network, mux.Close, nil
}
