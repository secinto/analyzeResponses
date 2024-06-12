package analyze

import (
	"bufio"
	"encoding/json"
	"fmt"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	log           = NewLogger()
	appConfig     Config
	commonHeaders = []string{"Host", "Server", "Last-Modified", "Content-Length", "Content-Type", "User-Agent",
		"Cache-Control", "Connection", "Date", "Pragma", "Strict-Transport-Security", "Expires", "X-Content-Type-Options",
		"X-Xss-Protection", "X-Frame-Options", "Referrer-Policy", "Etag", "Last-Modified", "Feature-Policy", "Accept-Ranges",
		"Accept-Charset", "Accept-Encoding", "User-Agent", "Vary", "Content-Security-Policy", "Content-Language",
		"Age", "Access-Control-Allow-Origin", "Referer", "X-Content-Type-Options", "Location", "Permissions-Policy",
		"Via", "Www-Authenticate", "Set-Cookie", "Transfer-Encoding"}
	extractHeaders = []string{"Server", "Last-Modified", "Content-Security-Policy", "Access-Control-Allow-Origin",
		"Via", "Set-Cookie", "Www-Authenticate"}
)

//-------------------------------------------
//	Initialization methods
//-------------------------------------------

func NewAnalyzer(options *Options) (*Analyzer, error) {
	finder := &Analyzer{options: options}
	finder.initialize(options.SettingsFile)
	return finder, nil
}

func (p *Analyzer) initialize(configLocation string) {
	appConfig = loadConfigFrom(configLocation)
	if !strings.HasSuffix(appConfig.ProjectsPath, "/") {
		appConfig.ProjectsPath = appConfig.ProjectsPath + "/"
	}
	p.options.BaseFolder = appConfig.ProjectsPath + p.options.Project
	if !strings.HasSuffix(p.options.BaseFolder, "/") {
		p.options.BaseFolder = p.options.BaseFolder + "/"
	}
}

func loadConfigFrom(location string) Config {
	var config Config
	var yamlFile []byte
	var err error

	yamlFile, err = os.ReadFile(location)
	if err != nil {
		yamlFile, err = os.ReadFile(defaultSettingsLocation)
		if err != nil {
			log.Fatalf("yamlFile.Get err   #%v ", err)
		}
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	if &config == nil {
		config = Config{
			ProjectsPath: "/checkfix/projects",
		}
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	return config
}

//-------------------------------------------
//			Main functions methods
//-------------------------------------------

func (p *Analyzer) Analyze() error {
	log.Infof("Getting findings for project %s", p.options.Project)
	if p.options.Project != "" {
		filepath.WalkDir(p.options.BaseFolder+"/responses/domains/response", p.analyseFileContent)
		responseInfo, _ := json.MarshalIndent(p.responseInfos, "", " ")
		WriteToFileInProject(p.options.BaseFolder+"findings/responseInfos.json", string(responseInfo))
	} else {
		log.Fatal("Project must be specified")
	}
	return nil
}

func (p *Analyzer) analyseFileContent(file string, d fs.DirEntry, err error) error {
	if !strings.HasSuffix(file, "index.txt") && strings.HasSuffix(file, ".txt") {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			log.Infof("Analyzing file %s", file)
			content := readFileToString(file)

			if len(content) > 0 {
				var lastLine string
				lastIndex := strings.LastIndex(content, "\n")
				if lastIndex >= len(content)-1 {
					lastIndex = lastIndexAt(content, "\n", lastIndex-100)
				}

				if lastIndex >= len(content)-1 {
					lastLine = ""
				} else {
					lastLine = content[lastIndex+1:]
				}

				responseInfo := ResponseInfos{
					Url: lastLine,
				}

				if lastLine != "" {
					input, err := url.Parse(lastLine)

					if err != nil {
						log.Infof("Couldn't parse input as URL: %s", lastLine)
					} else {
						responseInfo.Host = input.Hostname()
						if input.Port() == "" {
							if input.Scheme == "http" {
								//Assume that it is 80 since it is HTTP
								responseInfo.Port = "80"
							} else if input.Scheme == "https" {
								//Assume that it is 443 since it is HTTPS
								responseInfo.Port = "443"
							} else {
								log.Errorf("Protocol not handled: %s", input.Scheme)
							}

						} else {
							responseInfo.Port = input.Port()
						}
					}
				} else {
					log.Errorf("No request URL info found %s", file)
				}

				foundDate := findCopyrightDate(content, file)

				if foundDate != "" {
					log.Debugf("Text around found index %s", foundDate)
					r := regexp.MustCompile("(19|20)\\d{2}")
					matches := r.FindAllString(foundDate, -1)
					if matches != nil {
						responseInfo.Year = matches[len(matches)-1]
						log.Infof("Last modified year %s set for %s", responseInfo.Year, responseInfo.Url)
					} else {
						log.Debugf("Content didn't contain a year. %s", foundDate)
					}
				} else {
					log.Debugf("No copyright info for %s", file)
				}

				analyzeHeaders(content, &responseInfo)

				p.responseInfos = append(p.responseInfos, responseInfo)
			}
		}
	}
	return nil
}

func analyzeHeaders(content string, info *ResponseInfos) {
	var nonStandardHeaders []string
	var interestingHeaders []string
	var statusCodes []string
	var locations []string
	var httpMethods []string
	var hosts []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	var serverHeaders = false
	var clientHeaders = false
	for scanner.Scan() {

		line := scanner.Text()
		if strings.HasPrefix(line, "HTTP/") {
			serverHeaders = true
		} else if strings.Contains(line, "HTTP/") {
			clientHeaders = true
		}
		if line == "" {
			serverHeaders = false
			clientHeaders = false
		}
		if serverHeaders {

			if strings.Contains(line, ":") {
				parts := strings.Split(line, ":")
				if len(parts) > 0 {
					if !slices.Contains(commonHeaders, parts[0]) {
						nonStandardHeaders = AppendIfMissing(nonStandardHeaders, strings.TrimSpace(line))
					}
					if slices.Contains(extractHeaders, parts[0]) {
						interestingHeaders = AppendIfMissing(interestingHeaders, line)
						if strings.HasPrefix(line, "Last-Modified") && info.Year == "" {
							r := regexp.MustCompile("(19|20)\\d{2}")
							matches := r.FindAllString(line, -1)
							if matches != nil {
								info.Year = matches[len(matches)-1]
								log.Infof("Last modified year %s set for %s", info.Year, info.Url)
							}
						}
					}
				}
			} else {
				parts := strings.Split(line, " ")
				statusCodes = append(statusCodes, strings.TrimSpace(parts[1]))
			}
		} else if clientHeaders {
			if strings.Contains(line, ":") {
				parts := strings.Split(line, ":")
				if len(parts) > 0 {
					if parts[0] == "Host" {
						hosts = append(hosts, strings.TrimSpace(parts[1]))
					}
				}
			} else {
				parts := strings.Split(line, " ")
				locations = append(locations, strings.TrimSpace(parts[1]))
				httpMethods = append(httpMethods, strings.TrimSpace(parts[0]))
			}
		}
	}
	if len(nonStandardHeaders) > 0 {
		log.Debugf("Server at URL %s responded with non standard headers: %s", info.Url, nonStandardHeaders)
		info.NonStandardHeaders = nonStandardHeaders
	}
	if len(interestingHeaders) > 0 {
		log.Debugf("Server at URL %s responded with interesting headers: %s", info.Url, interestingHeaders)
		info.InterestingHeaders = interestingHeaders
	}
	if len(statusCodes) > 0 {
		log.Debugf("Server at URL %s responded with following status codes: %s", info.Url, statusCodes)
		info.StatusCodes = statusCodes
	}
	if len(locations) > 0 {
		log.Debugf("Server at URL %s was requested with following locations: %s", info.Url, locations)
		info.Locations = locations
	}
	if len(httpMethods) > 0 {
		log.Debugf("Server at URL %s was requested with following HTTP methods: %s", info.Url, httpMethods)
		info.HttpMethods = httpMethods
	}
	if len(hosts) > 0 {
		log.Debugf("Server at URL %s was requested with following host headers: %s", info.Url, hosts)
		info.Hosts = hosts
	}
}

func findCopyrightDate(content string, file string) string {
	var found = ""
	// Regex to check for a year between 1999-2099
	//r := regexp.MustCompile("(19|20)\\d{2}")

	if index := strings.LastIndex(content, "©"); index > 0 {
		log.Debugf("Found copyright sign at index %d of file %s", index, file)
		if len(content) < index+101 {
			found = content[index-20 : len(content)-1]
		} else {
			found = content[index-20 : index+100]
		}
	}
	if index := strings.LastIndex(content, "Copyright"); index > 0 {
		log.Debugf("Found copyright text at index %d of file %s", index, file)
		if len(content) < index+100 {
			found = content[index-20 : len(content)-1]
		} else {
			found = content[index-20 : index+100]
		}
	}
	if index := strings.LastIndex(content, "&copy;"); index > 0 {
		log.Debugf("Found &copy; text at index %d of file %s", index, file)
		if len(content) < index+100 {
			found = content[index-20 : len(content)-1]
		} else {
			found = content[index-20 : index+100]
		}
	}
	return found
}

func readFileToString(filename string) string {
	b, err := os.ReadFile(filename) // just pass the file name
	if err != nil {
		fmt.Print(err)
	}

	str := string(b) // convert content to a 'string'
	return str
}
