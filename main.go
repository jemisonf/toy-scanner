package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/mod/semver"
)

func main() {
	var image string

	flag.StringVar(&image, "image", "", "Image to scan")
	flag.Parse()

	ref, err := name.ParseReference(image)

	if err != nil {
		fmt.Printf("Error parsing image name: %s\n", err.Error())
		os.Exit(1)
	}

	docker_image, err := remote.Image(ref)

	if err != nil {
		fmt.Printf("Error fetching image: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("%+v\n", docker_image)

	manifest, err := docker_image.Manifest()

	if manifest != nil {
		report, _ := AlpineScanner(*manifest, docker_image)
		fmt.Printf("%+v\n", report)

		vulns, err := AlpineMatcher(*report)

		fmt.Println(err)
		fmt.Println(vulns)
	}
}

type AlpineReport struct {
	Packages []AlpinePackage
	Version  string
}

type AlpinePackage struct {
	Name    string
	Version string
}

func AlpineScanner(manifest v1.Manifest, image v1.Image) (*AlpineReport, error) {
	layers := []v1.Layer{}
	for _, layer_desc := range manifest.Layers {
		layer, err := image.LayerByDigest(layer_desc.Digest)

		if err != nil {
			return nil, fmt.Errorf("Error fetching layer %s: %w", layer_desc.Digest, err.Error())
		}
		layers = append(layers, layer)
	}

	packages := []AlpinePackage{}
	var version string
	for _, layer := range layers {

		reader, _ := layer.Uncompressed()

		tar_reader := tar.NewReader(reader)

		header, err := tar_reader.Next()
		for header != nil && err == nil {
			if header.Name == "lib/apk/db/installed" {
				contents, _ := io.ReadAll(tar_reader)

				entries := bytes.Split(contents, []byte("\n\n"))

				for _, entry := range entries {
					lines := bytes.Split(entry, []byte("\n"))

					var name, version string

					for _, line := range lines {
						if len(line) == 0 {
							continue
						}
						switch line[0] {
						case 'P':
							name = string(line[2:])
						case 'V':
							version = string(line[2:])
						}
					}

					if name != "" && version != "" {
						packages = append(packages, AlpinePackage{Name: name, Version: version})
					}
				}
			}
			if header.Name == "etc/os-release" {
				contents, _ := io.ReadAll(tar_reader)

				lines := bytes.Split(contents, []byte("\n"))

				for _, line := range lines {
					if strings.Contains(string(line), "VERSION_ID") {
						fmt.Sscanf(string(line), "VERSION_ID=%s", &version)
					}
				}
			}
			header, err = tar_reader.Next()
		}

	}

	return &AlpineReport{
		Packages: packages,
		Version:  version,
	}, nil
}

type Vulnerability struct {
	CVEs        []string
	PackageName string
	Version     string
}

type SecDBReport struct {
	Packages []SecDBPackage
}

type SecDBPackage struct {
	Pkg SecDBPkg
}

type SecDBPkg struct {
	Name     string
	Secfixes map[string][]string
}

func AlpineMatcher(report AlpineReport) ([]Vulnerability, error) {
	vulnerable_packages := []Vulnerability{}

	majorMinorVersion := semver.MajorMinor("v" + report.Version)

	client := http.Client{}

	secDBURL, err := url.Parse(fmt.Sprintf("https://secdb.alpinelinux.org/%s/main.json", majorMinorVersion))

	if err != nil {
		return nil, err
	}

	res, err := client.Do(&http.Request{
		Method: "GET",
		URL:    secDBURL,
	})

	if res.StatusCode > 399 {
		return nil, fmt.Errorf("error fetching Alpine SecDB data for version %s, got code %d", majorMinorVersion, res.StatusCode)
	}

	responseBytes, err := io.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	var contents SecDBReport

	err = json.Unmarshal(responseBytes, &contents)

	if err != nil {
		return nil, err
	}

	for _, installed_package := range report.Packages {
		for _, secdb_package := range contents.Packages {
			if secdb_package.Pkg.Name == installed_package.Name {
				if CVEs, ok := secdb_package.Pkg.Secfixes[installed_package.Version]; ok {
					vulnerable_packages = append(vulnerable_packages, Vulnerability{
						PackageName: installed_package.Name,
						CVEs:        CVEs,
					})
				}
			}
		}
	}

	return vulnerable_packages, nil
}
