package main

type SignatureManifest struct {
	Layers []struct {
		Digest      string `json:"digest"`
		Annotations struct {
			Signature string `json:"dev.cosignproject.cosign/signature"`
		} `json:"annotations"`
	} `json:"layers"`
}
