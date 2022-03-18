package main

import (
	"archive/tar"
	"bytes"
	"flag"
	"fmt"
	"io"
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
		report := AlpineScanner(*manifest, docker_image)
		fmt.Println(report)
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

func AlpineScanner(manifest v1.Manifest, image v1.Image) AlpineReport {
	layers := []v1.Layer{}
	for _, layer_desc := range manifest.Layers {
		layer, err := image.LayerByDigest(layer_desc.Digest)

		if err != nil {
			fmt.Printf("Error fetching layer %s: %s", layer_desc.Digest, err.Error())
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
						version = strings.Replace(strings.Replace(string(line), "VERSION_ID=", "", 1), "\"", "", 2)
					}
				}
			}
			header, err = tar_reader.Next()
		}

	}

	return AlpineReport{Packages: packages, Version: semver.MajorMinor("v" + version)}
}
