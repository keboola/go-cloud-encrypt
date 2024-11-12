package cloudencrypt

type MetadataKV struct {
	Key   string
	Value string
}

func buildMetadataMap(metadata ...MetadataKV) map[string]string {
	out := make(map[string]string)
	for _, kv := range metadata {
		out[kv.Key] = kv.Value
	}
	return out
}
