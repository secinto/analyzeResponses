package analyze

const VERSION = "0.1"

type Config struct {
	S2SPath string `yaml:"s2s_path,omitempty"`
}

type Analyzer struct {
	options       *Options
	responseInfos []ResponseInfos
}

type ResponseInfos struct {
	Host               string
	Port               string
	Url                string
	Year               string
	InterestingHeaders []string
	NonStandardHeaders []string
}
