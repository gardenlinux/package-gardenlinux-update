package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"oras.land/oras-go/v2/registry/remote"
)

func getAvailableSpace(path string) (uint64, error) {
	var stat syscall.Statfs_t

	err := syscall.Statfs(path, &stat)
	if err != nil {
		return 0, err
	}

	available := stat.Bavail * uint64(stat.Bsize)
	return available, nil
}

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

func getCname(path string) (string, string, error) {
	os_release_content, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}

	os_release := parseOsRelease(string(os_release_content))
	version := os_release["GARDENLINUX_VERSION"]
	cname := strings.Trim(os_release["GARDENLINUX_CNAME"], "-"+version)

	return cname, version, nil
}

func checkEFI(expected_loader_entry string) error {
	_, err := os.Stat("sys/firmware/efi")
	if err != nil {
		return errors.New("not EFI booted")
	}

	data, err := os.ReadFile("/sys/firmware/efi/efivars/LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f")
	if err != nil {
		return errors.New("not booted with systemd EFI stub")
	}

	if string(data[4:]) == expected_loader_entry {
		return nil
	} else {
		return errors.New("booted entry does not match expected value")
	}
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

func getLayerByMediaType(repo *remote.Repository, ctx context.Context, digest string, media_type string) (string, uint64, error) {
	manifest, err := getManifest(repo, ctx, digest)
	if err != nil {
		return "", 0, err
	}

	var layer string
	var size uint64

	for _, entry := range manifest["layers"].([]interface{}) {
		item := entry.(map[string]interface{})
		item_digest := item["digest"].(string)
		item_size := uint64(item["size"].(float64))
		item_media_type := item["mediaType"].(string)

		if item_media_type == media_type {
			layer = item_digest
			size = item_size
			break
		}
	}

	return layer, size, nil
}

func getFilesWithPrefix(dir string, prefix string) ([]string, error) {
	var files []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), prefix) {
			files = append(files, entry.Name())
		}
	}

	return files, nil
}

type FileInfo struct {
	Filename       string
	Version        string
	BootBlessed    bool
	TriesRemaining int
}

func parseFileInfos(filenames []string, prefix string) []FileInfo {
	var result []FileInfo
	for _, filename := range filenames {
		name := strings.TrimSuffix(strings.TrimPrefix(filename, prefix+"-"), ".efi")
		parts := strings.Split(name, "+")
		version := parts[0]

		boot_blessed := true
		tries_remaining := 0

		if len(parts) > 1 {
			boot_blessed = false
			counting_part := strings.Split(parts[1], "-")[0]
			tries_remaining, _ = strconv.Atoi(counting_part)
		}

		result = append(result, FileInfo{
			Filename:       filename,
			Version:        version,
			BootBlessed:    boot_blessed,
			TriesRemaining: tries_remaining,
		})
	}
	return result
}

func compareVersions(v1 string, v2 string) int {
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")
	for i := 0; i < len(v1Parts) && i < len(v2Parts); i++ {
		v1Int, _ := strconv.Atoi(v1Parts[i])
		v2Int, _ := strconv.Atoi(v2Parts[i])
		if v1Int != v2Int {
			if v1Int > v2Int {
				return 1
			}
			return -1
		}
	}
	if len(v1Parts) > len(v2Parts) {
		return 1
	} else if len(v1Parts) < len(v2Parts) {
		return -1
	}
	return 0
}

func sortFileInfos(fileInfos []FileInfo) {
	sort.Slice(fileInfos, func(i, j int) bool {
		if fileInfos[i].BootBlessed != fileInfos[j].BootBlessed {
			return !fileInfos[i].BootBlessed
		}
		if fileInfos[i].TriesRemaining != fileInfos[j].TriesRemaining {
			return fileInfos[i].TriesRemaining < fileInfos[j].TriesRemaining
		}
		return compareVersions(fileInfos[i].Version, fileInfos[j].Version) < 0
	})
}

func garbageClean(directory, cname, current_version string, size_wanted int64) error {
	files, err := getFilesWithPrefix(directory, cname)
	if err != nil {
		return err
	}

	file_infos := parseFileInfos(files, cname)
	sortFileInfos(file_infos)

	for _, file_info := range file_infos {
		if file_info.Version == current_version {
			continue
		}

		file_path := directory + "/" + file_info.Filename
		file_stat, err := os.Stat(file_path)
		if err != nil {
			return err
		}

		file_size := file_stat.Size()

		err = os.Remove(file_path)
		if err != nil {
			return err
		}

		fmt.Printf("cleaned up %s\n", file_path)

		size_wanted -= file_size
		if size_wanted <= 0 {
			break
		}
	}

	if size_wanted > 0 {
		return errors.New("garbage clean could not free enough space")
	}

	return nil
}

func main() {
	repo_url := flag.String("repo", "ghcr.io/gardenlinux/gl-oci", "OCI repository to download from")
	media_type := flag.String("media-type", "application/io.gardenlinux.uki", "artifact media type to fetch")
	target_dir := flag.String("target-dir", "/efi/EFI/Linux", "directory to write artifacts to")
	os_release_path := flag.String("os-release", "/etc/os-release", "alternative path where the os-release file is read from")
	skip_efi_check := flag.Bool("skip-efi-check", false, "skip performing EFI safety checks")

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

	cname, current_version, err := getCname(*os_release_path)
	if err != nil {
		panic(err)
	}

	if !*skip_efi_check {
		err = checkEFI(cname + "-" + current_version + ".efi")
		if err != nil {
			panic(err)
		}
	}

	ctx := context.Background()

	repo, err := remote.NewRepository(*repo_url)
	if err != nil {
		panic(err)
	}

	digest, err := getManifestDigestByCname(repo, ctx, version, cname)
	if err != nil {
		panic(err)
	}

	layer, size, err := getLayerByMediaType(repo, ctx, digest, *media_type)
	if err != nil {
		panic(err)
	}

	space_required := size + (1024 * 1024)

	target_path := *target_dir + "/" + cname + "-" + version + "+3.efi"

	space, err := getAvailableSpace(*target_dir)
	if err != nil {
		panic(err)
	}

	if space < space_required {
		space_wanted := space_required - space
		err := garbageClean(*target_dir, cname, current_version, int64(space_wanted))
		if err != nil {
			panic(err)
		}
	}

	fmt.Printf("downloading %s@%s -> %s\n", *repo_url, layer, target_path)

	layer_descriptor, err := repo.Blobs().Resolve(ctx, layer)
	if err != nil {
		panic(err)
	}

	layer_stream, err := repo.Fetch(ctx, layer_descriptor)
	if err != nil {
		panic(err)
	}
	defer layer_stream.Close()

	target_file, err := os.Create(target_path)
	if err != nil {
		panic(err)
	}
	defer target_file.Close()

	_, err = io.Copy(target_file, layer_stream)
	if err != nil {
		panic(err)
	}
}
