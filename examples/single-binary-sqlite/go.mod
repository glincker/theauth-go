module github.com/glincker/theauth-go/examples/single-binary-sqlite

go 1.26.0

replace github.com/glincker/theauth-go/v2 => ../..

replace github.com/glincker/theauth-go/storage/sqlite => ../../storage/sqlite

require (
	github.com/glincker/theauth-go/storage/sqlite v0.0.0
	github.com/glincker/theauth-go/v2 v2.6.0
	modernc.org/sqlite v1.60.1
)

require (
	github.com/beevik/etree v1.8.1 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/crewjam/saml v0.5.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.6 // indirect
	github.com/go-chi/chi/v5 v5.3.2 // indirect
	github.com/go-webauthn/webauthn v0.13.4 // indirect
	github.com/go-webauthn/x v0.1.23 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.5 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	github.com/pquerna/otp v1.5.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/russellhaering/goxmldsig v1.6.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
