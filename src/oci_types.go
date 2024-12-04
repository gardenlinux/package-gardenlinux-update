package main

type SignatureManifest struct {
	Layers []struct {
		Digest      string `json:"digest"`
		Annotations struct {
			Signature string `json:"dev.cosignproject.cosign/signature"`
		} `json:"annotations"`
	} `json:"layers"`
}

type SignatureMessage struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}
