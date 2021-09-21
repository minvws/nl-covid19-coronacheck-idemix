module github.com/minvws/nl-covid19-coronacheck-idemix

go 1.14

require (
	github.com/go-errors/errors v1.4.0
	github.com/minvws/base45-go v0.1.0
	github.com/privacybydesign/gabi v0.0.0-20200823153621-467696543652
	github.com/spf13/cobra v1.1.3
	github.com/spf13/viper v1.7.1
)

replace github.com/privacybydesign/gabi v0.0.0-20200823153621-467696543652 => github.com/minvws/gabi v0.0.0-20210921115139-d07d39e65855
