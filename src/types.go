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

type Index struct {
	Manifests []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
		Platform  struct {
			Architecture string `json:"architecture"`
			Os           string `json:"os"`
		} `json:"platform"`
		Annotations struct {
			Cname        string `json:"cname"`
			Architecture string `json:"architecture"`
			FeatureSet   string `json:"feature_set"`
		} `json:"annotations,omitempty"`
	} `json:"manifests"`
}

type Manifest struct {
	MediaType string `json:"mediaType"`
	Config    struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	} `json:"layers"`
}
