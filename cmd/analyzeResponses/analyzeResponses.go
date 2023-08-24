package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/secinto/analyzeResponses/analyze"
)

func main() {
	// Parse the command line flags and read config files
	options := analyze.ParseOptions()

	newDiffer, err := analyze.NewAnalyzer(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create analyzeResponses: %s\n", err)
	}

	err = newDiffer.Analyze()
	if err != nil {
		gologger.Fatal().Msgf("Could not analyzeResponses: %s\n", err)
	}
}
