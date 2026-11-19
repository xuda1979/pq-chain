// Package store persists the canonical chain: an append-only block journal
// plus periodic state snapshots. Nodes replay the journal through the
// open-source state machine (state.ApplyBlock) to reconstruct any height,
// then speed up restart by loading the latest snapshot.
//
// Layout under dir:
//
//	chain.journal   one canonical block encoding per record, length-prefixed
//	LOCK            advisory lock to prevent two writers
//
// Crash safety: each Append is a single atomic record (length prefix +
// block encoding) followed by fsync; a torn tail record left by a crash
// mid-append is detected on Open and truncated, so a crash loses at most
// the in-flight block, never corrupts the chain.
//
// Consensus-bound: Append validates strictly increasing height (last+1),
// so the journal can never contain gaps; a node restoring from it always
// reconstructs a contiguous chain.
package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/xuda1979/pq-chain/protocol"
)

// MaxRecordLen bounds a journal record (a full block). Consensus blocks
// are far smaller (protocol.MaxBlockSize = 1 MiB); the journal cap stops a
// corrupted length prefix from triggering a huge allocation before the
// per-record size check runs.
const MaxRecordLen = 1 << 24 // 16 MiB

var (
	// ErrEmpty is returned when the journal has no records yet.
	ErrEmpty = errors.New("store: empty chain")
	// ErrOutOfRange is returned for heights beyond the recorded range.
	ErrOutOfRange = errors.New("store: height out of range")
	// ErrLocked is returned when another process holds the store lock.
	ErrLocked = errors.New("store: directory locked by another writer")
)

// Store is an open journal handle. Not safe for concurrent writers; one
// node process owns it.
type Store struct {
	dir         string
	file        *os.File
	lock        *os.File
	last        uint64           // last recorded height, 0 while empty
	index       map[uint64]int64 // height -> file offset, built during recover
	appendOff   int64            // offset where the next record will start
}

// Open opens (or creates) the store in dir. Only one process may hold it
// open for writing; a second Open fails with ErrLocked.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("store: mkdir: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, "LOCK"), os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		if os.IsExist(err) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("store: lock: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "chain.journal"), os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		lock.Close()
		return nil, fmt.Errorf("store: open journal: %w", err)
	}
	s := &Store{dir: dir, file: f, lock: lock, index: make(map[uint64]int64), appendOff: 0}
	if err := s.recover(); err != nil {
		f.Close()
		lock.Close()
		os.Remove(lock.Name())
		return nil, err
	}
	return s, nil
}

// Close releases the store and its lock.
func (s *Store) Close() error {
	s.file.Sync()
	err := s.file.Close()
	lockErr := os.Remove(s.lock.Name())
	s.lock.Close()
	if err != nil {
		return fmt.Errorf("store: close journal: %w", err)
	}
	if lockErr != nil && !os.IsNotExist(lockErr) {
		return fmt.Errorf("store: release lock: %w", lockErr)
	}
	return nil
}

// Height returns the highest recorded block height (0 when empty).
func (s *Store) Height() uint64 { return s.last }

// Empty reports whether the journal has no blocks.
func (s *Store) Empty() bool { return s.last == 0 }

// recover scans the journal building the height->offset index, and
// truncates any torn tail record left by a crash mid-append.
func (s *Store) recover() error {
	off := int64(0)
	for {
		var lenBuf [4]byte
		if _, err := s.file.ReadAt(lenBuf[:], off); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("store: read length: %w", err)
		}
		s.appendOff = off
		n := binary.LittleEndian.Uint32(lenBuf[:])
		if n == 0 || n > MaxRecordLen {
			// Corrupt tail: truncate from here and stop.
			return s.truncateAt(off)
		}
		hdr := make([]byte, n)
		if _, err := s.file.ReadAt(hdr, off+4); err != nil {
			if err == io.EOF {
				// Torn record: length promised n bytes but file ended.
				return s.truncateAt(off)
			}
			return fmt.Errorf("store: read record: %w", err)
		}
		var b protocol.Block
		if err := b.Unmarshal(hdr); err != nil {
			return fmt.Errorf("store: corrupt record at offset %d: %w", off, err)
		}
		if h := b.Header.Height; h <= s.last {
			return fmt.Errorf("store: duplicate/non-increasing height %d after %d", h, s.last)
		}
		s.last = b.Header.Height
		s.index[b.Header.Height] = off
		off += 4 + int64(n)
	}
	s.appendOff = off
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("store: sync after recover: %w", err)
	}
	return nil
}

// truncateAt cuts the file at off (removing a torn/corrupt tail) and syncs.
func (s *Store) truncateAt(off int64) error {
	if err := s.file.Truncate(off); err != nil {
		return fmt.Errorf("store: truncate torn tail: %w", err)
	}
	if _, err := s.file.Seek(off, io.SeekStart); err != nil {
		return fmt.Errorf("store: seek after truncate: %w", err)
	}
	s.appendOff = off
	return s.file.Sync()
}

// Append writes one block to the journal atomically. Height must be
// exactly last+1 (or 1 on an empty journal), so the journal never has gaps.
func (s *Store) Append(b *protocol.Block) error {
	if b.Header.Height != s.last+1 {
		return fmt.Errorf("store: append height %d, want %d", b.Header.Height, s.last+1)
	}
	rec := b.Marshal()
	if len(rec) > MaxRecordLen {
		return fmt.Errorf("store: block %d bytes exceeds %d", len(rec), MaxRecordLen)
	}
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(rec)))
	if _, err := s.file.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("store: write length: %w", err)
	}
	if _, err := s.file.Write(rec); err != nil {
		return fmt.Errorf("store: write record: %w", err)
	}
	if err := s.file.Sync(); err != nil {
		return fmt.Errorf("store: sync: %w", err)
	}
	off := s.appendOff
	s.last = b.Header.Height
	s.index[b.Header.Height] = off
	s.appendOff += 4 + int64(len(rec))
	return nil
}


// Get reads the block at height (1-based). Returns ErrOutOfRange for
// heights beyond the journal, ErrEmpty for an empty journal.
func (s *Store) Get(height uint64) (*protocol.Block, error) {
	if s.last == 0 {
		return nil, ErrEmpty
	}
	if height < 1 || height > s.last {
		return nil, ErrOutOfRange
	}
	off, ok := s.index[height]
	if !ok {
		return nil, fmt.Errorf("store: no index entry for height %d", height)
	}
	rec, err := s.readRecordAt(off)
	if err != nil {
		return nil, err
	}
	var b protocol.Block
	if err := b.Unmarshal(rec); err != nil {
		return nil, fmt.Errorf("store: corrupt record at height %d: %w", height, err)
	}
	return &b, nil
}

// readRecordAt reads the length-prefixed record at off.
func (s *Store) readRecordAt(off int64) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := s.file.ReadAt(lenBuf[:], off); err != nil {
		return nil, fmt.Errorf("store: read length at %d: %w", off, err)
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n == 0 || n > MaxRecordLen {
		return nil, fmt.Errorf("store: bad length %d at %d", n, off)
	}
	buf := make([]byte, n)
	if _, err := s.file.ReadAt(buf, off+4); err != nil {
		return nil, fmt.Errorf("store: read record at %d: %w", off, err)
	}
	return buf, nil
}
