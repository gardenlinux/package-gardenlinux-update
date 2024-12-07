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
	version, ok := os_release["GARDENLINUX_VERSION"]
	if !ok {
		return "", "", errors.New("GARDENLINUX_VERSION missing from os-release")
	}

	cname, ok := os_release["GARDENLINUX_CNAME"]
	if !ok {
		return "", "", errors.New("GARDENLINUX_CNAME missing from os-release")
	}

	cname = strings.Trim(cname, "-"+version)

	return cname, version, nil
}

func checkEFI(expected_loader_entry string) error {
	_, err := os.Stat("/sys/firmware/efi")
	if err != nil {
		return errors.New("not EFI booted")
	}

	data, err := os.ReadFile("/sys/firmware/efi/efivars/LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f")
	if err != nil {
		return errors.New("not booted with systemd EFI stub")
	}

	loader_entry := string(data[4:])
	if loader_entry != expected_loader_entry {
		return errors.New("booted entry does not match expected value")
	}

	return nil
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

const ERR_INVALID_ARGUMENTS = 1
const ERR_SYSTEM_FAILURE = 2
const ERR_NETWORK_PROBLEMS = 3

func main() {
	flag_set := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag_set.SetOutput(os.Stderr)

	repo_url := flag_set.String("repo", "ghcr.io/gardenlinux/gardenlinux", "OCI repository to download from")
	media_type := flag_set.String("media-type", "application/io.gardenlinux.uki", "artifact media type to fetch")
	target_dir := flag_set.String("target-dir", "/efi/EFI/Linux", "directory to write artifacts to")
	os_release_path := flag_set.String("os-release", "/etc/os-release", "alternative path where the os-release file is read from")
	skip_efi_check := flag_set.Bool("skip-efi-check", false, "skip performing EFI safety checks")

	flag_set.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <version>\n\n", os.Args[0])
		flag_set.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nexit codes:\n\t0: success\n\t1: invalid arguments\n\t2: system failure\n\t3: network problems\n")
	}

	if err := flag_set.Parse(os.Args[1:]); err != nil {
		os.Exit(ERR_INVALID_ARGUMENTS)
	}

	if flag_set.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: version argument is required")
		os.Exit(ERR_INVALID_ARGUMENTS)
	}
	version := flag_set.Arg(0)

	cname, current_version, err := getCname(*os_release_path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_INVALID_ARGUMENTS)
	}

	if !*skip_efi_check {
		err = checkEFI(cname + "-" + current_version + ".efi")
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(ERR_SYSTEM_FAILURE)
		}
	}

	ctx := context.Background()

	repo, err := remote.NewRepository(*repo_url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_INVALID_ARGUMENTS)
	}

	digest, err := getManifestDigestByCname(repo, ctx, version, cname)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_NETWORK_PROBLEMS)
	}

	layer, size, err := getLayerByMediaType(repo, ctx, digest, *media_type)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_NETWORK_PROBLEMS)
	}

	space_required := size + (1024 * 1024)

	target_path := *target_dir + "/" + cname + "-" + version + "+3.efi"

	space, err := getAvailableSpace(*target_dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_SYSTEM_FAILURE)
	}

	if space < space_required {
		space_wanted := space_required - space
		err := garbageClean(*target_dir, cname, current_version, int64(space_wanted))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(ERR_SYSTEM_FAILURE)
		}
	}

	fmt.Printf("downloading %s@%s -> %s\n", *repo_url, layer, target_path)

	layer_descriptor, err := repo.Blobs().Resolve(ctx, layer)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_NETWORK_PROBLEMS)
	}

	layer_stream, err := repo.Fetch(ctx, layer_descriptor)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_NETWORK_PROBLEMS)
	}
	defer layer_stream.Close()

	target_file, err := os.Create(target_path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_SYSTEM_FAILURE)
	}
	defer target_file.Close()

	_, err = io.Copy(target_file, layer_stream)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_NETWORK_PROBLEMS)
	}
}
