package client

type RemoteStore interface {
	GetMeta(name string) (stream io.ReadClose, size int64, err error)
	//GetTarget(path string) (stream io.ReadCloser, size int64, err error)
}
