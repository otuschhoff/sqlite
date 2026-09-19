package vfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"unsafe"

	"modernc.org/libc"
	sqlite3 "modernc.org/sqlite/lib"
)

const encryptedSectorSize = aes.BlockSize

type encryptedVFSConfig struct {
	parent uintptr
	key    []byte
}

type encryptedFile struct {
	base   sqlite3_file
	handle uintptr
}

type encryptedFileState struct {
	methods *sqlite3_io_methods
	cipher  cipher.Block
}

var encryptedIO = sqlite3_io_methods{iVersion: 3}

func init() {
	setCallback(&encryptedIO.xClose, encryptedClose)
	setCallback(&encryptedIO.xRead, encryptedRead)
	setCallback(&encryptedIO.xWrite, encryptedWrite)
	setCallback(&encryptedIO.xTruncate, encryptedTruncate)
	setCallback(&encryptedIO.xSync, encryptedSync)
	setCallback(&encryptedIO.xFileSize, encryptedFileSize)
	setCallback(&encryptedIO.xLock, encryptedLock)
	setCallback(&encryptedIO.xUnlock, encryptedUnlock)
	setCallback(&encryptedIO.xCheckReservedLock, encryptedCheckReservedLock)
	setCallback(&encryptedIO.xFileControl, encryptedFileControl)
	setCallback(&encryptedIO.xSectorSize, encryptedSectorSizeOf)
	setCallback(&encryptedIO.xDeviceCharacteristics, encryptedDeviceCharacteristics)
	setCallback(&encryptedIO.xShmMap, encryptedShmMap)
	setCallback(&encryptedIO.xShmLock, encryptedShmLock)
	setCallback(&encryptedIO.xShmBarrier, encryptedShmBarrier)
	setCallback(&encryptedIO.xShmUnmap, encryptedShmUnmap)
	setCallback(&encryptedIO.xFetch, encryptedFetch)
	setCallback(&encryptedIO.xUnfetch, encryptedUnfetch)
}

func setCallback[T any](slot *uintptr, callback T) {
	*(*T)(unsafe.Pointer(slot)) = callback
}

func callback[T any](pointer uintptr) T {
	return *(*T)(unsafe.Pointer(&struct{ uintptr }{pointer}))
}

func encryptedState(pFile uintptr) *encryptedFileState {
	return getObject((*encryptedFile)(unsafe.Pointer(pFile)).handle).(*encryptedFileState)
}

func encryptedParentFile(pFile uintptr) uintptr {
	return pFile + unsafe.Sizeof(encryptedFile{})
}

func encryptedConfig(pVfs uintptr) *encryptedVFSConfig {
	return getObject((*sqlite3_vfs)(unsafe.Pointer(pVfs)).pAppData).(*encryptedVFSConfig)
}

func encryptedParentVFS(pVfs uintptr) uintptr {
	return encryptedConfig(pVfs).parent
}

func encryptedOpen(tls *libc.TLS, pVfs, zName, pFile uintptr, flags int32, pOutFlags uintptr) int32 {
	file := (*encryptedFile)(unsafe.Pointer(pFile))
	*file = encryptedFile{}
	config := encryptedConfig(pVfs)
	parentFile := encryptedParentFile(pFile)
	parent := (*sqlite3_vfs)(unsafe.Pointer(config.parent))
	rc := callback[func(*libc.TLS, uintptr, uintptr, uintptr, int32, uintptr) int32](parent.xOpen)(tls, config.parent, zName, parentFile, flags, pOutFlags)
	methods := (*sqlite3_file)(unsafe.Pointer(parentFile)).pMethods
	if methods == 0 {
		return rc
	}
	fileKey := sha256.New()
	fileKey.Write([]byte("modernc.org/sqlite encrypted file\x00"))
	fileKey.Write(config.key)
	var fileType [4]byte
	binary.BigEndian.PutUint32(fileType[:], uint32(flags&encryptedFileTypeMask))
	fileKey.Write(fileType[:])
	cipher, err := aes.NewCipher(fileKey.Sum(nil))
	if err != nil {
		_ = callback[func(*libc.TLS, uintptr) int32]((*sqlite3_io_methods)(unsafe.Pointer(methods)).xClose)(tls, parentFile)
		return sqlite3.SQLITE_IOERR
	}
	file.handle = addObject(&encryptedFileState{methods: (*sqlite3_io_methods)(unsafe.Pointer(methods)), cipher: cipher})
	file.base.pMethods = uintptr(unsafe.Pointer(&encryptedIO))
	return rc
}

const encryptedFileTypeMask = sqlite3.SQLITE_OPEN_MAIN_DB |
	sqlite3.SQLITE_OPEN_TEMP_DB |
	sqlite3.SQLITE_OPEN_TRANSIENT_DB |
	sqlite3.SQLITE_OPEN_MAIN_JOURNAL |
	sqlite3.SQLITE_OPEN_TEMP_JOURNAL |
	sqlite3.SQLITE_OPEN_SUBJOURNAL |
	sqlite3.SQLITE_OPEN_SUPER_JOURNAL |
	sqlite3.SQLITE_OPEN_WAL

func encryptedClose(tls *libc.TLS, pFile uintptr) int32 {
	state := encryptedState(pFile)
	rc := callback[func(*libc.TLS, uintptr) int32](state.methods.xClose)(tls, encryptedParentFile(pFile))
	removeObject((*encryptedFile)(unsafe.Pointer(pFile)).handle)
	(*encryptedFile)(unsafe.Pointer(pFile)).handle = 0
	return rc
}

func encryptedRead(tls *libc.TLS, pFile, zBuf uintptr, amount int32, offset sqlite_int64) int32 {
	if amount <= 0 {
		return sqlite3.SQLITE_OK
	}
	if offset < 0 {
		return sqlite3.SQLITE_IOERR_READ
	}
	state := encryptedState(pFile)
	parentFile := encryptedParentFile(pFile)
	output := (*libc.RawMem)(unsafe.Pointer(zBuf))[:amount]
	var size sqlite_int64
	if rc := callback[func(*libc.TLS, uintptr, uintptr) int32](state.methods.xFileSize)(tls, parentFile, uintptr(unsafe.Pointer(&size))); rc != sqlite3.SQLITE_OK {
		return rc
	}
	if offset >= size {
		clear(output)
		return sqlite3.SQLITE_IOERR_SHORT_READ
	}
	readAmount := sqlite_int64(amount)
	result := int32(sqlite3.SQLITE_OK)
	if available := size - offset; readAmount > available {
		readAmount = available
		result = sqlite3.SQLITE_IOERR_SHORT_READ
	}
	if rc := callback[func(*libc.TLS, uintptr, uintptr, int32, sqlite_int64) int32](state.methods.xRead)(tls, parentFile, zBuf, int32(readAmount), offset); rc != sqlite3.SQLITE_OK {
		clear(output)
		return rc
	}
	transformAt(state.cipher, output[:readAmount], offset)
	if result != sqlite3.SQLITE_OK {
		clear(output[readAmount:])
	}
	return result
}

func encryptedWrite(tls *libc.TLS, pFile, zBuf uintptr, amount int32, offset sqlite_int64) int32 {
	if amount <= 0 {
		return sqlite3.SQLITE_OK
	}
	if offset < 0 {
		return sqlite3.SQLITE_IOERR_WRITE
	}
	state := encryptedState(pFile)
	input := (*libc.RawMem)(unsafe.Pointer(zBuf))[:amount]
	encrypted := make([]byte, amount)
	copy(encrypted, input)
	transformAt(state.cipher, encrypted, offset)
	return callback[func(*libc.TLS, uintptr, uintptr, int32, sqlite_int64) int32](state.methods.xWrite)(tls, encryptedParentFile(pFile), uintptr(unsafe.Pointer(&encrypted[0])), amount, offset)
}

func encryptedTruncate(tls *libc.TLS, pFile uintptr, size sqlite_int64) int32 {
	state := encryptedState(pFile)
	return callback[func(*libc.TLS, uintptr, sqlite_int64) int32](state.methods.xTruncate)(tls, encryptedParentFile(pFile), size)
}

func transformAt(block cipher.Block, data []byte, offset sqlite_int64) {
	var counter [aes.BlockSize]byte
	var stream [aes.BlockSize]byte
	for len(data) > 0 {
		blockIndex := uint64(offset / aes.BlockSize)
		withinBlock := int(offset % aes.BlockSize)
		binary.BigEndian.PutUint64(counter[aes.BlockSize-8:], blockIndex)
		block.Encrypt(stream[:], counter[:])
		count := min(len(data), aes.BlockSize-withinBlock)
		for index := range count {
			data[index] ^= stream[withinBlock+index]
		}
		data = data[count:]
		offset += sqlite_int64(count)
	}
}

func encryptedSync(tls *libc.TLS, pFile uintptr, flags int32) int32 {
	state := encryptedState(pFile)
	return callback[func(*libc.TLS, uintptr, int32) int32](state.methods.xSync)(tls, encryptedParentFile(pFile), flags)
}

func encryptedFileSize(tls *libc.TLS, pFile, pSize uintptr) int32 {
	state := encryptedState(pFile)
	return callback[func(*libc.TLS, uintptr, uintptr) int32](state.methods.xFileSize)(tls, encryptedParentFile(pFile), pSize)
}

func encryptedLock(tls *libc.TLS, pFile uintptr, lock int32) int32 {
	state := encryptedState(pFile)
	return callback[func(*libc.TLS, uintptr, int32) int32](state.methods.xLock)(tls, encryptedParentFile(pFile), lock)
}

func encryptedUnlock(tls *libc.TLS, pFile uintptr, lock int32) int32 {
	state := encryptedState(pFile)
	return callback[func(*libc.TLS, uintptr, int32) int32](state.methods.xUnlock)(tls, encryptedParentFile(pFile), lock)
}

func encryptedCheckReservedLock(tls *libc.TLS, pFile, pResult uintptr) int32 {
	state := encryptedState(pFile)
	return callback[func(*libc.TLS, uintptr, uintptr) int32](state.methods.xCheckReservedLock)(tls, encryptedParentFile(pFile), pResult)
}

func encryptedFileControl(tls *libc.TLS, pFile uintptr, operation int32, argument uintptr) int32 {
	state := encryptedState(pFile)
	return callback[func(*libc.TLS, uintptr, int32, uintptr) int32](state.methods.xFileControl)(tls, encryptedParentFile(pFile), operation, argument)
}

func encryptedSectorSizeOf(tls *libc.TLS, pFile uintptr) int32 {
	state := encryptedState(pFile)
	size := callback[func(*libc.TLS, uintptr) int32](state.methods.xSectorSize)(tls, encryptedParentFile(pFile))
	if size < encryptedSectorSize {
		return encryptedSectorSize
	}
	return size
}

func encryptedDeviceCharacteristics(tls *libc.TLS, pFile uintptr) int32 {
	state := encryptedState(pFile)
	capabilities := callback[func(*libc.TLS, uintptr) int32](state.methods.xDeviceCharacteristics)(tls, encryptedParentFile(pFile))
	const safe = sqlite3.SQLITE_IOCAP_ATOMIC | sqlite3.SQLITE_IOCAP_ATOMIC512 | sqlite3.SQLITE_IOCAP_IMMUTABLE | sqlite3.SQLITE_IOCAP_SEQUENTIAL | sqlite3.SQLITE_IOCAP_SUBPAGE_READ | sqlite3.SQLITE_IOCAP_BATCH_ATOMIC | sqlite3.SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN
	return capabilities & safe
}

func encryptedShmMap(tls *libc.TLS, pFile uintptr, page, pageSize, extend int32, result uintptr) int32 {
	state := encryptedState(pFile)
	if state.methods.iVersion < 2 || state.methods.xShmMap == 0 {
		return sqlite3.SQLITE_IOERR_SHMMAP
	}
	return callback[func(*libc.TLS, uintptr, int32, int32, int32, uintptr) int32](state.methods.xShmMap)(tls, encryptedParentFile(pFile), page, pageSize, extend, result)
}

func encryptedShmLock(tls *libc.TLS, pFile uintptr, offset, count, flags int32) int32 {
	state := encryptedState(pFile)
	if state.methods.iVersion < 2 || state.methods.xShmLock == 0 {
		return sqlite3.SQLITE_IOERR_SHMLOCK
	}
	return callback[func(*libc.TLS, uintptr, int32, int32, int32) int32](state.methods.xShmLock)(tls, encryptedParentFile(pFile), offset, count, flags)
}

func encryptedShmBarrier(tls *libc.TLS, pFile uintptr) {
	state := encryptedState(pFile)
	if state.methods.iVersion >= 2 && state.methods.xShmBarrier != 0 {
		callback[func(*libc.TLS, uintptr)](state.methods.xShmBarrier)(tls, encryptedParentFile(pFile))
	}
}

func encryptedShmUnmap(tls *libc.TLS, pFile uintptr, deleteFlag int32) int32 {
	state := encryptedState(pFile)
	if state.methods.iVersion < 2 || state.methods.xShmUnmap == 0 {
		return sqlite3.SQLITE_OK
	}
	return callback[func(*libc.TLS, uintptr, int32) int32](state.methods.xShmUnmap)(tls, encryptedParentFile(pFile), deleteFlag)
}

func encryptedFetch(_ *libc.TLS, _ uintptr, _ sqlite_int64, _ int32, result uintptr) int32 {
	*(*uintptr)(unsafe.Pointer(result)) = 0
	return sqlite3.SQLITE_OK
}

func encryptedUnfetch(_ *libc.TLS, _ uintptr, _ sqlite_int64, _ uintptr) int32 {
	return sqlite3.SQLITE_OK
}

func encryptedDelete(tls *libc.TLS, pVfs, zName uintptr, syncDir int32) int32 {
	parent := encryptedParentVFS(pVfs)
	return callback[func(*libc.TLS, uintptr, uintptr, int32) int32]((*sqlite3_vfs)(unsafe.Pointer(parent)).xDelete)(tls, parent, zName, syncDir)
}

func encryptedAccess(tls *libc.TLS, pVfs, zName uintptr, flags int32, result uintptr) int32 {
	parent := encryptedParentVFS(pVfs)
	return callback[func(*libc.TLS, uintptr, uintptr, int32, uintptr) int32]((*sqlite3_vfs)(unsafe.Pointer(parent)).xAccess)(tls, parent, zName, flags, result)
}

func encryptedFullPathname(tls *libc.TLS, pVfs, zName uintptr, size int32, output uintptr) int32 {
	parent := encryptedParentVFS(pVfs)
	return callback[func(*libc.TLS, uintptr, uintptr, int32, uintptr) int32]((*sqlite3_vfs)(unsafe.Pointer(parent)).xFullPathname)(tls, parent, zName, size, output)
}

func encryptedDlOpen(tls *libc.TLS, pVfs, zName uintptr) uintptr {
	parent := encryptedParentVFS(pVfs)
	return callback[func(*libc.TLS, uintptr, uintptr) uintptr]((*sqlite3_vfs)(unsafe.Pointer(parent)).xDlOpen)(tls, parent, zName)
}

func encryptedDlError(tls *libc.TLS, pVfs uintptr, size int32, output uintptr) {
	parent := encryptedParentVFS(pVfs)
	callback[func(*libc.TLS, uintptr, int32, uintptr)]((*sqlite3_vfs)(unsafe.Pointer(parent)).xDlError)(tls, parent, size, output)
}

func encryptedDlSym(tls *libc.TLS, pVfs, handle, zSymbol uintptr) uintptr {
	parent := encryptedParentVFS(pVfs)
	return callback[func(*libc.TLS, uintptr, uintptr, uintptr) uintptr]((*sqlite3_vfs)(unsafe.Pointer(parent)).xDlSym)(tls, parent, handle, zSymbol)
}

func encryptedDlClose(tls *libc.TLS, pVfs, handle uintptr) {
	parent := encryptedParentVFS(pVfs)
	callback[func(*libc.TLS, uintptr, uintptr)]((*sqlite3_vfs)(unsafe.Pointer(parent)).xDlClose)(tls, parent, handle)
}

func encryptedRandomness(tls *libc.TLS, pVfs uintptr, size int32, output uintptr) int32 {
	parent := encryptedParentVFS(pVfs)
	return callback[func(*libc.TLS, uintptr, int32, uintptr) int32]((*sqlite3_vfs)(unsafe.Pointer(parent)).xRandomness)(tls, parent, size, output)
}

func encryptedSleep(tls *libc.TLS, pVfs uintptr, microseconds int32) int32 {
	parent := encryptedParentVFS(pVfs)
	return callback[func(*libc.TLS, uintptr, int32) int32]((*sqlite3_vfs)(unsafe.Pointer(parent)).xSleep)(tls, parent, microseconds)
}

func encryptedCurrentTime(tls *libc.TLS, pVfs, result uintptr) int32 {
	parent := encryptedParentVFS(pVfs)
	return callback[func(*libc.TLS, uintptr, uintptr) int32]((*sqlite3_vfs)(unsafe.Pointer(parent)).xCurrentTime)(tls, parent, result)
}

func encryptedGetLastError(tls *libc.TLS, pVfs uintptr, size int32, output uintptr) int32 {
	parent := encryptedParentVFS(pVfs)
	return callback[func(*libc.TLS, uintptr, int32, uintptr) int32]((*sqlite3_vfs)(unsafe.Pointer(parent)).xGetLastError)(tls, parent, size, output)
}

func encryptedCurrentTimeInt64(tls *libc.TLS, pVfs, result uintptr) int32 {
	parent := encryptedParentVFS(pVfs)
	method := (*sqlite3_vfs)(unsafe.Pointer(parent)).xCurrentTimeInt64
	if method == 0 {
		return sqlite3.SQLITE_NOTFOUND
	}
	return callback[func(*libc.TLS, uintptr, uintptr) int32](method)(tls, parent, result)
}

func encryptedSetSystemCall(tls *libc.TLS, pVfs, zName, method uintptr) int32 {
	parent := encryptedParentVFS(pVfs)
	callbackPointer := (*sqlite3_vfs)(unsafe.Pointer(parent)).xSetSystemCall
	if callbackPointer == 0 {
		return sqlite3.SQLITE_NOTFOUND
	}
	return callback[func(*libc.TLS, uintptr, uintptr, uintptr) int32](callbackPointer)(tls, parent, zName, method)
}

func encryptedGetSystemCall(tls *libc.TLS, pVfs, zName uintptr) uintptr {
	parent := encryptedParentVFS(pVfs)
	method := (*sqlite3_vfs)(unsafe.Pointer(parent)).xGetSystemCall
	if method == 0 {
		return 0
	}
	return callback[func(*libc.TLS, uintptr, uintptr) uintptr](method)(tls, parent, zName)
}

func encryptedNextSystemCall(tls *libc.TLS, pVfs, zName uintptr) uintptr {
	parent := encryptedParentVFS(pVfs)
	method := (*sqlite3_vfs)(unsafe.Pointer(parent)).xNextSystemCall
	if method == 0 {
		return 0
	}
	return callback[func(*libc.TLS, uintptr, uintptr) uintptr](method)(tls, parent, zName)
}

// EncryptedFS is a registered SQLite VFS that encrypts file payloads at rest.
type EncryptedFS struct {
	cname        uintptr
	cvfs         uintptr
	configHandle uintptr
	tls          *libc.TLS
	closed       int32
}

// NewEncrypted registers an AES-256-CTR VFS over SQLite's default native VFS.
// Key must contain at least 32 bytes. The returned name is selected with the
// vfs DSN parameter. Keys are held in memory and never placed in the DSN.
//
// Use one EncryptedFS per database family and close all databases using it
// before calling Close. Database, journal, WAL, and temporary file streams use
// separate derived keys. Encryption is length preserving and provides
// confidentiality, but not authentication or rollback protection.
func NewEncrypted(key []byte) (name string, _ *EncryptedFS, _ error) {
	if len(key) < 32 {
		return "", nil, errors.New("encrypted VFS key must contain at least 32 bytes")
	}
	mu.Lock()
	defer mu.Unlock()

	tls := libc.NewTLS()
	parent := sqlite3.Xsqlite3_vfs_find(tls, 0)
	if parent == 0 {
		tls.Close()
		return "", nil, errors.New("SQLite default VFS is unavailable")
	}
	derivedKey := sha256.Sum256(append([]byte("modernc.org/sqlite encrypted VFS\x00"), key...))
	config := &encryptedVFSConfig{parent: parent, key: append([]byte(nil), derivedKey[:]...)}
	handle := addObject(config)
	name = fmt.Sprintf("encrypted%x", handle)
	cname, err := libc.CString(name)
	if err != nil {
		removeObject(handle)
		tls.Close()
		return "", nil, err
	}
	cvfs := libc.Xcalloc(tls, 1, libc.Tsize_t(unsafe.Sizeof(sqlite3_vfs{})))
	if cvfs == 0 {
		removeObject(handle)
		libc.Xfree(tls, cname)
		tls.Close()
		return "", nil, errors.New("allocate encrypted SQLite VFS")
	}
	parentVFS := (*sqlite3_vfs)(unsafe.Pointer(parent))
	vfs := (*sqlite3_vfs)(unsafe.Pointer(cvfs))
	*vfs = *parentVFS
	vfs.szOsFile = int32(unsafe.Sizeof(encryptedFile{})) + parentVFS.szOsFile
	vfs.zName = cname
	vfs.pAppData = handle
	setCallback(&vfs.xOpen, encryptedOpen)
	setCallback(&vfs.xDelete, encryptedDelete)
	setCallback(&vfs.xAccess, encryptedAccess)
	setCallback(&vfs.xFullPathname, encryptedFullPathname)
	setCallback(&vfs.xDlOpen, encryptedDlOpen)
	setCallback(&vfs.xDlError, encryptedDlError)
	setCallback(&vfs.xDlSym, encryptedDlSym)
	setCallback(&vfs.xDlClose, encryptedDlClose)
	setCallback(&vfs.xRandomness, encryptedRandomness)
	setCallback(&vfs.xSleep, encryptedSleep)
	setCallback(&vfs.xCurrentTime, encryptedCurrentTime)
	setCallback(&vfs.xGetLastError, encryptedGetLastError)
	setCallback(&vfs.xCurrentTimeInt64, encryptedCurrentTimeInt64)
	setCallback(&vfs.xSetSystemCall, encryptedSetSystemCall)
	setCallback(&vfs.xGetSystemCall, encryptedGetSystemCall)
	setCallback(&vfs.xNextSystemCall, encryptedNextSystemCall)
	if rc := sqlite3.Xsqlite3_vfs_register(tls, cvfs, libc.Bool32(false)); rc != sqlite3.SQLITE_OK {
		removeObject(handle)
		libc.Xfree(tls, cname)
		libc.Xfree(tls, cvfs)
		tls.Close()
		return "", nil, fmt.Errorf("registering encrypted VFS %s: %d", name, rc)
	}
	return name, &EncryptedFS{cname: cname, cvfs: cvfs, configHandle: handle, tls: tls}, nil
}

// Close unregisters the encrypted VFS and clears its in-memory key copy.
func (f *EncryptedFS) Close() error {
	if f == nil || atomic.SwapInt32(&f.closed, 1) != 0 {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	rc := sqlite3.Xsqlite3_vfs_unregister(f.tls, f.cvfs)
	config := getObject(f.configHandle).(*encryptedVFSConfig)
	clear(config.key)
	removeObject(f.configHandle)
	libc.Xfree(f.tls, f.cname)
	libc.Xfree(f.tls, f.cvfs)
	f.tls.Close()
	if rc != sqlite3.SQLITE_OK {
		return fmt.Errorf("unregistering encrypted VFS: %d", rc)
	}
	return nil
}
