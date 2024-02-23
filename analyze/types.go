package analyze

const VERSION = "0.2.1"

type Config struct {
	ProjectsPath string `yaml:"projects_path,omitempty"`
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
