package registry

/*
  This entire document is because the oras default hybridStore
  which is at https://github.com/deislabs/oras/blob/173c010570c48e4aa18ce186cae8cc812f8e8b6e/pkg/oras/store.go
  in oras has 2 shortcomings:
    https://github.com/deislabs/oras/issues/225
    https://github.com/deislabs/oras/issues/226
  when those are resolved, this all can go away.
*/

import (
	"context"
	"errors"
	"io"
	"time"

	orascontent "oras.land/oras-go/pkg/content"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
)

type cacheStore struct {
	cache    *orascontent.Memorystore
	provider content.Provider
	ingester content.Ingester
}

func newCacheStoreFromProvider(provider content.Provider) *cacheStore {
	return &cacheStore{
		cache:    orascontent.NewMemoryStore(),
		provider: provider,
	}
}

func newCacheStoreFromIngester(ingester content.Ingester) *cacheStore {
	return &cacheStore{
		cache:    orascontent.NewMemoryStore(),
		ingester: ingester,
	}
}

func (s *cacheStore) Set(desc ocispec.Descriptor, content []byte) {
	s.cache.Set(desc, content)
}

// ReaderAt provides contents. If the requested descriptor is in the cache, it takes it from there, else from the wrapped provider.
func (s *cacheStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	readerAt, err := s.cache.ReaderAt(ctx, desc)
	if err == nil {
		return readerAt, nil
	}
	if s.provider != nil {
		return s.provider.ReaderAt(ctx, desc)
	}
	return nil, err
}

// Writer begins or resumes the active writer identified by desc. If it is one of the mediatypes that indicates a manifest
// or list, whether docker manifest/manifest list or oci manifest/index, then it caches it but also writes it to the wrapped
// ingester.
func (s *cacheStore) Writer(ctx context.Context, opts ...content.WriterOpt) (content.Writer, error) {
	var wOpts content.WriterOpts
	for _, opt := range opts {
		if err := opt(&wOpts); err != nil {
			return nil, err
		}
	}

	if isAllowedMediaType(wOpts.Desc.MediaType, ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex, images.MediaTypeDockerSchema2Manifest, images.MediaTypeDockerSchema2ManifestList) || s.ingester == nil {
		cacheWriter, err := s.cache.Writer(ctx, opts...)
		if err != nil {
			return nil, err
		}
		ingesterWriter, err := s.ingester.Writer(ctx, opts...)
		if err != nil {
			return nil, err
		}
		return newTeeWriter(wOpts.Desc, cacheWriter, ingesterWriter), nil
	}
	return s.ingester.Writer(ctx, opts...)
}

// TODO: implement (needed to create a content.Store)
// TODO: do not return empty content.Info
// Abort completely cancels the ingest operation targeted by ref.
func (s *cacheStore) Info(ctx context.Context, dgst digest.Digest) (content.Info, error) {
	return content.Info{}, nil
}

// TODO: implement (needed to create a content.Store)
// Update updates mutable information related to content.
// If one or more fieldpaths are provided, only those
// fields will be updated.
// Mutable fields:
//  labels.*
func (s *cacheStore) Update(ctx context.Context, info content.Info, fieldpaths ...string) (content.Info, error) {
	return content.Info{}, errors.New("not yet implemented: Update (content.Store interface)")
}

// TODO: implement (needed to create a content.Store)
// Walk will call fn for each item in the content store which
// match the provided filters. If no filters are given all
// items will be walked.
func (s *cacheStore) Walk(ctx context.Context, fn content.WalkFunc, filters ...string) error {
	return errors.New("not yet implemented: Walk (content.Store interface)")
}

// TODO: implement (needed to create a content.Store)
// Delete removes the content from the store.
func (s *cacheStore) Delete(ctx context.Context, dgst digest.Digest) error {
	return errors.New("not yet implemented: Delete (content.Store interface)")
}

// TODO: implement (needed to create a content.Store)
func (s *cacheStore) Status(ctx context.Context, ref string) (content.Status, error) {
	// Status returns the status of the provided ref.
	return content.Status{}, errors.New("not yet implemented: Status (content.Store interface)")
}

// TODO: implement (needed to create a content.Store)
// ListStatuses returns the status of any active ingestions whose ref match the
// provided regular expression. If empty, all active ingestions will be
// returned.
func (s *cacheStore) ListStatuses(ctx context.Context, filters ...string) ([]content.Status, error) {
	return []content.Status{}, errors.New("not yet implemented: ListStatuses (content.Store interface)")
}

// TODO: implement (needed to create a content.Store)
// Abort completely cancels the ingest operation targeted by ref.
func (s *cacheStore) Abort(ctx context.Context, ref string) error {
	return errors.New("not yet implemented: Abort (content.Store interface)")
}

func isAllowedMediaType(mediaType string, allowedMediaTypes ...string) bool {
	if len(allowedMediaTypes) == 0 {
		return true
	}
	for _, allowedMediaType := range allowedMediaTypes {
		if mediaType == allowedMediaType {
			return true
		}
	}
	return false
}

// teeWriter tees the content to one or more content.Writer
type teeWriter struct {
	writers  []content.Writer
	digester digest.Digester
	status   content.Status
}

func newTeeWriter(desc ocispec.Descriptor, writers ...content.Writer) *teeWriter {
	now := time.Now()
	return &teeWriter{
		writers:  writers,
		digester: digest.Canonical.Digester(),
		status: content.Status{
			Total:     desc.Size,
			StartedAt: now,
			UpdatedAt: now,
		},
	}
}

func (t *teeWriter) Close() error {
	g := new(errgroup.Group)
	for _, w := range t.writers {
		w := w // closure issues, see https://golang.org/doc/faq#closures_and_goroutines
		g.Go(func() error {
			return w.Close()
		})
	}
	return g.Wait()
}

func (t *teeWriter) Write(p []byte) (n int, err error) {
	g := new(errgroup.Group)
	for _, w := range t.writers {
		w := w // closure issues, see https://golang.org/doc/faq#closures_and_goroutines
		g.Go(func() error {
			n, err := w.Write(p[:])
			if err != nil {
				return err
			}
			if n != len(p) {
				return io.ErrShortWrite
			}
			return nil
		})
	}
	err = g.Wait()
	n = len(p)
	if err != nil {
		return n, err
	}
	_, _ = t.digester.Hash().Write(p[:n])
	t.status.Offset += int64(len(p))
	t.status.UpdatedAt = time.Now()

	return n, nil
}

// Digest may return empty digest or panics until committed.
func (t *teeWriter) Digest() digest.Digest {
	return t.digester.Digest()
}

func (t *teeWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	g := new(errgroup.Group)
	for _, w := range t.writers {
		w := w // closure issues, see https://golang.org/doc/faq#closures_and_goroutines
		g.Go(func() error {
			return w.Commit(ctx, size, expected, opts...)
		})
	}
	return g.Wait()
}

// Status returns the current state of write
func (t *teeWriter) Status() (content.Status, error) {
	return t.status, nil
}

// Truncate updates the size of the target blob
func (t *teeWriter) Truncate(size int64) error {
	g := new(errgroup.Group)
	for _, w := range t.writers {
		w := w // closure issues, see https://golang.org/doc/faq#closures_and_goroutines
		g.Go(func() error {
			return w.Truncate(size)
		})
	}
	return g.Wait()
}
