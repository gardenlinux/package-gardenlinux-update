package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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

	cname = strings.TrimSuffix(cname, "-"+version)

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

	var utf8_data []byte
	for i := 4; i < len(data); i += 2 {
		utf8_data = append(utf8_data, data[i])
	}

	loader_entry := string(utf8_data)
	loader_entry = strings.Trim(loader_entry, "\x00")

	if loader_entry != expected_loader_entry {
		return errors.New("booted entry does not match expected value")
	}

	return nil
}

func getManifestBytes(repo *remote.Repository, ctx context.Context, ref string) ([]byte, error) {
	manifestDescriptor, err := repo.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	manifestStream, err := repo.Fetch(ctx, manifestDescriptor)
	if err != nil {
		return nil, err
	}
	defer manifestStream.Close()

	manifestContent, err := io.ReadAll(manifestStream)
	if err != nil {
		return nil, err
	}

	return manifestContent, nil
}

func getBlobBytes(repo *remote.Repository, ctx context.Context, ref string) ([]byte, error) {
	manifestDescriptor, err := repo.Blobs().Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	manifestStream, err := repo.Fetch(ctx, manifestDescriptor)
	if err != nil {
		return nil, err
	}
	defer manifestStream.Close()

	blobContent, err := io.ReadAll(manifestStream)
	if err != nil {
		return nil, err
	}

	return blobContent, nil
}

func getManifestDigestByCname(repo *remote.Repository, ctx context.Context, tag string, cname string) (string, error) {
	indexData, err := getManifestBytes(repo, ctx, tag)
	if err != nil {
		return "", err
	}

	index := Index{}
	err = json.Unmarshal(indexData, &index)
	if err != nil {
		return "", err
	}

	var digest string

	for _, entry := range index.Manifests {
		if strings.HasPrefix(entry.Annotations.Cname, cname) {
			digest = entry.Digest
			return digest, nil
		}
	}
	return "", errors.New("no manifest found for cname " + cname)
}

func getLayerByMediaType(repo *remote.Repository, ctx context.Context, digest string, media_type string) (string, uint64, error) {
	manifestData, err := getManifestBytes(repo, ctx, digest)
	if err != nil {
		return "", 0, err
	}

	manifest := Manifest{}
	err = json.Unmarshal(manifestData, &manifest)
	if err != nil {
		return "", 0, err
	}

	for _, layer := range manifest.Layers {
		if media_type == layer.MediaType {
			return layer.Digest, layer.Size, nil
		}
	}

	return "", 0, errors.New("no layer found for media type " + media_type)
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

func verifyManifest(repo *remote.Repository, ctx context.Context, digest, verificationKeyFile string) {
	signatureTag := strings.Replace(digest, "sha256:", "sha256-", 1) + ".sig"
	signatureManifestBytes, err := getManifestBytes(repo, ctx, signatureTag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_NETWORK_PROBLEMS)
	}

	signatureManifest := SignatureManifest{}
	err = json.Unmarshal(signatureManifestBytes, &signatureManifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_SYSTEM_FAILURE)
	}
	// types
	signatureStr := signatureManifest.Layers[0].Annotations.Signature
	signature, err := base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_SYSTEM_FAILURE)
	}

	messageHashStr := signatureManifest.Layers[0].Digest
	messageHashFromManifest, err := hex.DecodeString(strings.TrimPrefix(messageHashStr, "sha256:"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_SYSTEM_FAILURE)
	}

	// Here we pull the messageHashStr. This is insufficient for a proper signature verification. We have to
	// check the messages contents, validate that it contains the correct manifest digest, and then hash it ourselves.

	// 1. Get signed message
	message, err := getBlobBytes(repo, ctx, messageHashStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error fetching signed message:", err)
		os.Exit(ERR_NETWORK_PROBLEMS)
	}
	signatureMessage := SignatureMessage{}
	err = json.Unmarshal(message, &signatureMessage)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error unmarshalling signature message:", err)
		os.Exit(ERR_SYSTEM_FAILURE)
	}
	// 2. Check if correct digest is in the signed message
	if digest != signatureMessage.Critical.Image.DockerManifestDigest {
		fmt.Fprintln(os.Stderr, "Error during signature verification, the digest of the manifest to be verified ", digest, " is not equal to the digest that is in the signed message ", signatureMessage.Critical.Image.DockerManifestDigest)
		os.Exit(ERR_SYSTEM_FAILURE)
	}

	// 3. hash the signature message
	local_hash := sha256.Sum256(message)
	// 4. check if hash in signaturemanifest == locally computed hash of the message
	if !bytes.Equal(local_hash[:], messageHashFromManifest) {
		fmt.Fprintln(os.Stderr, "Error: the locally computed digest of the signed message (",
			messageHashFromManifest, "), does not match the digest from the signature manifest (",
			messageHashStr)
		os.Exit(ERR_SYSTEM_FAILURE)
	}

	pubKey := getVerificationKey(verificationKeyFile)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, local_hash[:], signature)
	if err == nil {
		fmt.Println("Verified OK")
	} else {
		fmt.Fprintln(os.Stderr, "Invalid signature:", err)
		os.Exit(ERR_SYSTEM_FAILURE)
	}

}

func getVerificationKey(verificationKeyFile string) *rsa.PublicKey {
	keyData, err := os.ReadFile(verificationKeyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error loading key:", err)
		os.Exit(ERR_SYSTEM_FAILURE)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		fmt.Fprintln(os.Stderr, "Error decoding pemdata.")
		os.Exit(ERR_SYSTEM_FAILURE)
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error parsing key:", err)
		os.Exit(ERR_SYSTEM_FAILURE)
	}
	return pubKey.(*rsa.PublicKey)
}

// Error codes should represent whether it is worth to retry (network errors for example) or not to retry (invalid arguments)
const (
	_                     = iota
	ERR_INVALID_ARGUMENTS // permanent
	ERR_SYSTEM_FAILURE    // permanent
	ERR_NETWORK_PROBLEMS  // retry makes sense
)

func main() {
	flag_set := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag_set.SetOutput(os.Stderr)

	repo_url := flag_set.String("repo", "ghcr.io/gardenlinux/gardenlinux", "OCI repository to download from")
	media_type := flag_set.String("media-type", "application/io.gardenlinux.uki", "artifact media type to fetch")
	target_dir := flag_set.String("target-dir", "/efi/EFI/Linux", "directory to write artifacts to")
	os_release_path := flag_set.String("os-release", "/etc/os-release", "alternative path where the os-release file is read from")
	skip_efi_check := flag_set.Bool("skip-efi-check", false, "skip performing EFI safety checks")
	verification_key_file := flag_set.String("verification-key", "/etc/gardenlinux/oci_signing_key.pem", "path to verification key file")

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

	// verify the signature here
	verifyManifest(repo, ctx, digest, *verification_key_file)

	layer, size, err := getLayerByMediaType(repo, ctx, digest, *media_type)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(ERR_NETWORK_PROBLEMS)
	}
	if layer == "" || size == 0 {
		fmt.Fprintln(os.Stderr, "No layer found for "+cname+" version: "+version+"  and mediatype"+*media_type+" on "+*repo_url)
		os.Exit(ERR_SYSTEM_FAILURE)
	}

	space_required := size + (1024 * 1024)

	target_path := *target_dir + "/" + cname + "-" + version + "+3.efi"

	space, err := getAvailableSpace(*target_dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error checking available space:", err)
		os.Exit(ERR_SYSTEM_FAILURE)
	}

	if space < space_required {
		space_wanted := space_required - space
		err := garbageClean(*target_dir, cname, current_version, int64(space_wanted))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error cleaning up:", err)
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
