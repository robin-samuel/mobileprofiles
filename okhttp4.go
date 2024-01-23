package mobileprofiles

import (
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

var Okhttp4Android5 = profiles.NewClientProfile(
	tls.ClientHelloID{
		Client:  "Okhttp4 Android",
		Version: "5.0.2",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						0x00, 0x01, 0x02,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(14),
						tls.CurveID(13),
						tls.CurveP521,
						tls.CurveID(11),
						tls.CurveID(12),
						tls.CurveP384,
						tls.CurveID(9),
						tls.CurveID(10),
						tls.CurveID(22),
						tls.CurveP256,
						tls.CurveID(8),
						tls.CurveID(6),
						tls.CurveID(7),
						tls.CurveID(20),
						tls.CurveID(21),
						tls.CurveID(4),
						tls.CurveID(5),
						tls.CurveID(18),
						tls.CurveID(19),
						tls.CurveID(1),
						tls.CurveID(2),
						tls.CurveID(3),
						tls.CurveID(15),
						tls.CurveID(16),
						tls.CurveID(17),
					}},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.PKCS1WithSHA512,
						0x602,
						tls.ECDSAWithP521AndSHA512,
						tls.PKCS1WithSHA384,
						0x502,
						tls.ECDSAWithP384AndSHA384,
						tls.PKCS1WithSHA256,
						0x402,
						tls.ECDSAWithP256AndSHA256,
						0x301,
						0x302,
						0x303,
						tls.PKCS1WithSHA1,
						0x202,
						tls.ECDSAWithSHA1,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				},
			}, nil
		},
	},
	map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	[]http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	[]string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	16711681,
	nil,
	nil,
)

var Okhttp4Android7 = profiles.NewClientProfile(
	tls.ClientHelloID{
		Client:  "Okhttp4 Android",
		Version: "7.0",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.PKCS1WithSHA512,
						tls.ECDSAWithP521AndSHA512,
						tls.PKCS1WithSHA384,
						tls.ECDSAWithP384AndSHA384,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP256AndSHA256,
						0x301,
						0x303,
						tls.PKCS1WithSHA1,
						tls.ECDSAWithSHA1,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveP256,
					}},
				},
			}, nil
		},
	},
	map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	[]http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	[]string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	16711681,
	nil,
	nil,
)

var Okhttp4Android71 = profiles.NewClientProfile(
	tls.ClientHelloID{
		Client:  "Okhttp4 Android",
		Version: "7.1.1",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.PKCS1WithSHA512,
						tls.ECDSAWithP521AndSHA512,
						tls.PKCS1WithSHA384,
						tls.ECDSAWithP384AndSHA384,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP256AndSHA256,
						0x301,
						0x303,
						tls.PKCS1WithSHA1,
						tls.ECDSAWithSHA1,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
				},
			}, nil
		},
	},
	map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	[]http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	[]string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	16711681,
	nil,
	nil,
)

var Okhttp4Android8 = profiles.NewClientProfile(
	tls.ClientHelloID{
		Client:  "Okhttp4 Android",
		Version: "8.0.0",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PKCS1WithSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.StatusRequestExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
				},
			}, nil
		},
	},
	map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	[]http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	[]string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	16711681,
	nil,
	nil,
)

var Okhttp4Android81 = profiles.NewClientProfile(
	tls.ClientHelloID{
		Client:  "Okhttp4 Android",
		Version: "8.1.0",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PKCS1WithSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.StatusRequestExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
				},
			}, nil
		},
	},
	map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	[]http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	[]string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	16711681,
	nil,
	nil,
)

var Okhttp4Android9 = profiles.NewClientProfile(
	tls.ClientHelloID{
		Client:  "Okhttp4 Android",
		Version: "9",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.StatusRequestExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
				},
			}, nil
		},
	},
	map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	[]http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	[]string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	16711681,
	nil,
	nil,
)

var Okhttp4Android10 = profiles.NewClientProfile(
	tls.ClientHelloID{
		Client:  "Okhttp4 Android",
		Version: "10",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	[]http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	[]string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	16711681,
	nil,
	nil,
)

var Okhttp4Android11 = profiles.NewClientProfile(
	tls.ClientHelloID{
		Client:  "Okhttp4 Android",
		Version: "11",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	[]http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	[]string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	16711681,
	nil,
	nil,
)

var Okhttp4Android12 = profiles.NewClientProfile(
	tls.ClientHelloID{
		Client:  "Okhttp4 Android",
		Version: "12",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	[]http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	[]string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	16711681,
	nil,
	nil,
)

var Okhttp4Android13 = profiles.NewClientProfile(
	tls.ClientHelloID{
		Client:  "Okhttp4 Android",
		Version: "13",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	[]http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	[]string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	16711681,
	nil,
	nil,
)

var Okhttp4Android14 = profiles.NewClientProfile(
	tls.ClientHelloID{
		Client:  "Okhttp4 Android",
		Version: "14",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	[]http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	[]string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	16711681,
	nil,
	nil,
)
