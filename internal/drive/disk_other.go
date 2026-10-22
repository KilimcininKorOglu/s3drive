//go:build !unix

package drive

import "errors"

func availableDisk(string) (int64, error) {
	return 0, errors.New("disk space checks are not supported on this platform")
}
