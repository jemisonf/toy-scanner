package main

import (
	"archive/tar"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
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

	if err != nil {
		fmt.Printf("Error fetching image manifest: %s\n", err.Error())
		os.Exit(1)
	}

	layers := []v1.Layer{}

	for _, layer_desc := range manifest.Layers {
		layer, err := docker_image.LayerByDigest(layer_desc.Digest)

		if err != nil {
			fmt.Printf("Error fetching layer %s: %s", layer_desc.Digest, err.Error())
		}
		layers = append(layers, layer)
	}

	first_layer := layers[0]

	reader, _ := first_layer.Uncompressed()

	tar_reader := tar.NewReader(reader)

	header, err := tar_reader.Next()
	for header != nil && err == nil {
		if header.Name == "lib/apk/db/installed" {
			fmt.Println("found dependencies file")

			contents, _ := io.ReadAll(tar_reader)

			fmt.Println(string(contents))
		}
		header, err = tar_reader.Next()
	}
}
