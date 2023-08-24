<h1 align="center">analyzeResponses</h1>
<h4 align="center">Tool for analyzing HTTP request/responses</h4>
<p align="center">
  
  <img src="https://img.shields.io/github/watchers/secinto/analyzeResponses?label=Watchers&style=for-the-badge" alt="GitHub Watchers">
  <img src="https://img.shields.io/github/stars/secinto/analyzeResponses?style=for-the-badge" alt="GitHub Stars">
  <img src="https://img.shields.io/github/license/secinto/analyzeResponses?style=for-the-badge" alt="GitHub License">
</p>

Developed by Stefan Kraxberger (https://twitter.com/skraxberger/)  

Released as open source by secinto GmbH - https://secinto.com/  
Released under Apache License version 2.0 see LICENSE for more information

Description
----
analyzeResponses is a GO tool which analyzes request/response files as written by HTTPx from project discovery.
It tries to identify the date of the file either via Copyright information, LastModified response Header or 
other useful means.

# Installation Instructions

`analyzeResponses` requires **go1.20** to install successfully. Run the following command to get the repo:

```sh
git clone https://github.com/secinto/analyzeResponses.git
cd analyzeResponses
go build
go install
```

or the following to directly install it from the command line:

```sh
go install -v github.com/secinto/analyzeResponses/cmd/analyzeResponses@latest
```

# Usage

```sh
analyzeResponses -help
```

This will display help for the tool. Here are all the switches it supports.


```console
analyze the responses obtained and stored by HTTPx for interesting data

Usage:
  ./analyzeResponses [flags]

Flags:
INPUT:
   -p, -project string  project name for metadata addition

DEBUG:
   -silent         show only results in output
   -version        show version of the project
   -v              show verbose output
   -nc, -no-color  disable colors in output

