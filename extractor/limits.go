package extractor

// Limits configures the resource bounds applied across extraction. The zero
// value is not usable; use DefaultLimits and override fields as needed.
//
// These limits protect against zip bombs, cyclic FAT chains, deeply nested
// stores and unbounded decompression. Reaching a limit is reported either as
// ErrLimitExceeded or as a diagnostic (soft limits), depending on the field.
type Limits struct {
	// MaxInputSize is the maximum total number of input bytes accepted.
	MaxInputSize int64
	// MaxContainerEntries caps the number of directory entries (CFB) or archive
	// entries (ZIP) examined.
	MaxContainerEntries int
	// MaxStreams caps the number of streams read from a single container.
	MaxStreams int
	// MaxDecompressed is the maximum total decompressed bytes per VBA stream
	// (both the dir stream and each module source stream).
	MaxDecompressed int64
	// MaxModuleSize caps the size of a single decoded module source.
	MaxModuleSize int64
	// MaxNestedDepth caps the depth of embedded OLE objects inside a container.
	MaxNestedDepth int
	// MaxZipRatio is the largest allowed ratio between declared uncompressed
	// and compressed size for a single archive entry. Entries above this ratio
	// are treated as decompression bombs.
	MaxZipRatio int64
}

// DefaultLimits returns conservative limits suitable for interactive analysis
// of typical office documents.
func DefaultLimits() Limits {
	return Limits{
		MaxInputSize:        256 << 20, // 256 MiB
		MaxContainerEntries: 1 << 16,   // 65536
		MaxStreams:          1 << 14,   // 16384
		MaxDecompressed:     256 << 20, // 256 MiB per stream
		MaxModuleSize:       32 << 20,  // 32 MiB
		MaxNestedDepth:      8,
		MaxZipRatio:         1000,
	}
}
