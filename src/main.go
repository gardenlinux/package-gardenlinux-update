package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"oras.land/oras-go/v2/registry/remote"
)

func parseOsRelease(data string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := parts[0]
		value := strings.Trim(strings.Trim(parts[1], `"`), `'`)
		result[key] = value
	}
	return result
}

func getCname(path string) (string, error) {
	os_release_content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	os_release := parseOsRelease(string(os_release_content))
	version := os_release["GARDENLINUX_VERSION"]
	cname := strings.Trim(os_release["GARDENLINUX_CNAME"], "-"+version)

	return cname, nil
}

func getManifest(repo *remote.Repository, ctx context.Context, ref string) (map[string]interface{}, error) {
	manifest_descriptor, err := repo.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}

	mainfest_stream, err := repo.Fetch(ctx, manifest_descriptor)
	if err != nil {
		return nil, err
	}
	defer mainfest_stream.Close()

	var manifest map[string]interface{}

	manifest_content, err := io.ReadAll(mainfest_stream)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(manifest_content, &manifest)
	if err != nil {
		return nil, err
	}

	return manifest, nil
}

func getManifestDigestByCname(repo *remote.Repository, ctx context.Context, tag string, cname string) (string, error) {
	manifest, err := getManifest(repo, ctx, tag)
	if err != nil {
		return "", err
	}

	var digest string

	for _, entry := range manifest["manifests"].([]interface{}) {
		item := entry.(map[string]interface{})
		item_digest := item["digest"].(string)
		item_annotations := item["annotations"].(map[string]interface{})
		item_cname := item_annotations["cname"].(string)

		if strings.HasPrefix(item_cname, cname) {
			digest = item_digest
			break
		}
	}

	return digest, nil
}

func getLayerByMediaType(repo *remote.Repository, ctx context.Context, digest string, media_type string) (string, error) {
	manifest, err := getManifest(repo, ctx, digest)
	if err != nil {
		return "", err
	}

	var layer string

	for _, entry := range manifest["layers"].([]interface{}) {
		item := entry.(map[string]interface{})
		item_digest := item["digest"].(string)
		item_media_type := item["mediaType"].(string)

		if item_media_type == media_type {
			layer = item_digest
			break
		}
	}

	return layer, nil
}

func downloadArtifact(target_path string, repo_url string, version string, cname string, media_type string) error {
	repo, err := remote.NewRepository(repo_url)
	if err != nil {
		return err
	}

	ctx := context.Background()

	digest, err := getManifestDigestByCname(repo, ctx, version, cname)
	if err != nil {
		return err
	}

	layer, err := getLayerByMediaType(repo, ctx, digest, media_type)
	if err != nil {
		return err
	}

	layer_descriptor, err := repo.Blobs().Resolve(ctx, layer)
	if err != nil {
		return err
	}

	fmt.Printf("downloading %s@%s -> %s\n", repo_url, layer_descriptor.Digest, target_path)

	layer_stream, err := repo.Fetch(ctx, layer_descriptor)
	if err != nil {
		return err
	}
	defer layer_stream.Close()

	target_file, err := os.Create(target_path)
	if err != nil {
		return err
	}
	defer target_file.Close()

	_, err = io.Copy(target_file, layer_stream)
	if err != nil {
		panic(err)
	}

	return nil
}

func main() {
	repo := flag.String("repo", "ghcr.io/gardenlinux/gl-oci", "OCI repository to download from")
	media_type := flag.String("media-type", "application/io.gardenlinux.uki", "artifact media type to fetch")
	target_dir := flag.String("target-dir", "/efi/EFI/Linux", "directory to write artifacts to")
	os_release_path := flag.String("os-release", "/etc/os-release", "alternative path where the os-release file is read from")
	override_cname := flag.String("cname", "", "override cname, by default the correct cname is determined automatically from /etc/os-release")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <version>\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Println("Error: version argument is required")
		os.Exit(1)
	}
	version := flag.Arg(0)

	var cname string
	if *override_cname == "" {
		current_cname, err := getCname(*os_release_path)
		if err != nil {
			panic(err)
		}

		cname = current_cname
	}

	target_path := *target_dir + "/" + cname + "-" + version + "+3.efi"

	if err := downloadArtifact(target_path, *repo, version, cname, *media_type); err != nil {
		panic(err)
	}
}
