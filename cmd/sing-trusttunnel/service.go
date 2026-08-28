package main

import (
	"context"
	stdTLS "crypto/tls"
	"net"
	"os"
	"os/signal"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/xchacha20-poly1305/sing-trusttunnel"
	"golang.org/x/net/http2"
)

func parseServerConfig(path string) (*ServerOptions, error) {
	options, err := parseConfig[ServerOptions](path)
	if err != nil {
		return nil, err
	}
	if len(options.Users) == 0 {
		return nil, E.New("missing users")
	}
	return options, nil
}

func runServer() (err error) {
	options, err := parseServerConfig(configPath)
	if err != nil {
		return E.Cause(err, "parse server config")
	}

	certificate, err := stdTLS.LoadX509KeyPair(options.Cert, options.Key)
	if err != nil {
		return E.Cause(err, "load server certificate")
	}
	tlsConfig := &TLSConfig{
		config: &stdTLS.Config{
			Certificates: []stdTLS.Certificate{certificate},
			NextProtos:   []string{http2.NextProtoTLS},
			ServerName:   options.ServerName,
		},
	}

	listenAddress := M.ParseSocksaddrHostPort(options.Listen, options.ListenPort)
	tcpListener, err := net.ListenTCP(N.NetworkTCP, listenAddress.TCPAddr())
	if err != nil {
		return E.Cause(err, "listen TCP")
	}
	defer tcpListener.Close()
	var packetConn net.PacketConn
	if options.ListenQUIC {
		packetConn, err = net.ListenUDP(N.NetworkUDP, listenAddress.UDPAddr())
		if err != nil {
			return E.Cause(err, "listen UDP")
		}
		defer packetConn.Close()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	myLogger := NewMyLogger(os.Stdout, "sing-trusttunnel server")
	router := NewRouter(newDefaultDialer(), myLogger)
	service := trusttunnel.NewService(trusttunnel.ServiceOptions{
		Ctx:                   ctx,
		Logger:                myLogger,
		Handler:               router,
		QUICCongestionControl: "bbr",
	})
	service.UpdateUsers(options.Users)
	err = service.Start(tcpListener, packetConn, tlsConfig)
	if err != nil {
		return E.Cause(err, "start service")
	}
	defer service.Close()

	<-ctx.Done()
	myLogger.DebugContext(ctx, "exiting...")
	return nil
}
