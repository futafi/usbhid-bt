// Copyright 2022-2024 Rafael G. Martins. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package usbhid

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

type deviceExtra struct {
	file *os.File
}

var (
	iocWrite    byte
	iocRead     byte
	iocSizeBits byte
	iocDirBits  byte

	iocNrShift   byte
	iocTypeShift byte
	iocSizeShift byte
	iocDirShift  byte
)

func init() {
	switch runtime.GOARCH {
	case "386":
		fallthrough
	case "amd64":
		fallthrough
	case "arm":
		fallthrough
	case "arm64":
		fallthrough
	case "loong64":
		fallthrough
	case "riscv64":
		fallthrough
	case "s390x":
		iocWrite = 1
		iocRead = 2
		iocSizeBits = 14
		iocDirBits = 2

	case "mips":
		fallthrough
	case "mips64":
		fallthrough
	case "mips64le":
		fallthrough
	case "mipsle":
		fallthrough
	case "ppc":
		fallthrough
	case "ppc64":
		fallthrough
	case "ppc64le":
		fallthrough
	case "sparc64":
		iocWrite = 4
		iocRead = 2
		iocSizeBits = 13
		iocDirBits = 3

	default:
		panic("usbhid: unsupported architecture")
	}

	iocNrShift = 0
	iocTypeShift = 8
	iocSizeShift = 16
	iocDirShift = 16 + iocSizeBits
}

func ioc(dir byte, typ byte, nr byte, size uint16) uint32 {
	dir = dir & (byte(math.Pow(2, float64(iocDirBits))) - 1)
	size = size & (uint16(math.Pow(2, float64(iocSizeBits))) - 1)
	return uint32(dir)<<iocDirShift | uint32(typ)<<iocTypeShift | uint32(nr)<<iocNrShift | uint32(size)<<iocSizeShift
}

func ioctl(fd uintptr, request uint, arg uintptr) (int, error) {
	rv, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(request), arg)
	if errno != 0 {
		return 0, fmt.Errorf("ioctl failed: 0x%x: %s", request, errno)
	}
	return int(rv), nil
}

func sysfsReadAsBytes(dir string, entry string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, entry))
}

func sysfsReadAsString(dir string, entry string) (string, error) {
	b, err := sysfsReadAsBytes(dir, entry)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func sysfsReadAsUint(dir string, entry string, base int, bitSize int) (uint64, error) {
	v, err := sysfsReadAsString(dir, entry)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(v, base, bitSize)
}

func sysfsReadAsHexUint16(dir string, entry string) (uint16, error) {
	v, err := sysfsReadAsUint(dir, entry, 16, 16)
	return uint16(v), err
}

func enumerate() ([]*Device, error) {
	rv := []*Device{}

	// Scan /sys/class/hidraw/ for all HID devices (USB + Bluetooth)
	hidrawDirs, err := filepath.Glob("/sys/class/hidraw/hidraw*")
	if err != nil {
		return nil, err
	}

	for _, hidrawDir := range hidrawDirs {
		deviceDir := filepath.Join(hidrawDir, "device")

		// Read uevent file to get HID_ID and HID_NAME
		uevent, err := sysfsReadAsString(deviceDir, "uevent")
		if err != nil {
			continue
		}

		var vendorId, productId, version uint16
		var hidName string

		// Parse uevent file
		// HID_ID format: BUS:VENDOR:PRODUCT (e.g., 0005:0000057E:00002006)
		for _, line := range strings.Split(uevent, "\n") {
			if strings.HasPrefix(line, "HID_ID=") {
				parts := strings.Split(strings.TrimPrefix(line, "HID_ID="), ":")
				if len(parts) == 3 {
					if v, err := strconv.ParseUint(parts[1], 16, 16); err == nil {
						vendorId = uint16(v)
					}
					if p, err := strconv.ParseUint(parts[2], 16, 16); err == nil {
						productId = uint16(p)
					}
				}
			} else if strings.HasPrefix(line, "HID_NAME=") {
				hidName = strings.TrimPrefix(line, "HID_NAME=")
			}
		}

		if vendorId == 0 || productId == 0 {
			continue
		}

		// Read report descriptor
		descriptor, err := sysfsReadAsBytes(deviceDir, "report_descriptor")
		if err != nil {
			continue
		}

		d := &Device{
			path:      filepath.Join("/dev", filepath.Base(hidrawDir)),
			vendorId:  vendorId,
			productId: productId,
			version:   version,
			product:   hidName,
		}
		d.usagePage, d.usage, d.reportInputLength, d.reportOutputLength, d.reportFeatureLength, d.reportWithId = hidParseReportDescriptor(descriptor)

		rv = append(rv, d)
	}

	return rv, nil
}

func (d *Device) open(lock bool) error {
	f, err := os.OpenFile(d.path, os.O_RDWR, 0755)
	if err != nil {
		return err
	}

	d.extra.file = f

	if lock {
		if err := syscall.Flock(int(d.extra.file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == syscall.EWOULDBLOCK {
			return ErrDeviceLocked
		}
	}
	return nil
}

func (d *Device) isOpen() bool {
	return d.extra.file != nil
}

func (d *Device) close() error {
	if err := d.extra.file.Close(); err != nil {
		return err
	}
	d.extra.file = nil

	return nil
}

func (d *Device) getInputReport() (byte, []byte, error) {
	buflen := d.reportInputLength
	if d.reportWithId {
		buflen++
	}

	buf := make([]byte, buflen)

	n, err := d.extra.file.Read(buf)
	if err != nil {
		return 0, nil, err
	}

	if d.reportWithId {
		return buf[0], buf[1:n], nil
	}
	return 0, buf[:n], nil
}

func (d *Device) setOutputReport(reportId byte, data []byte) error {
	buf := append([]byte{reportId}, data...)
	_, err := d.extra.file.Write(buf)
	return err
}

func (d *Device) getFeatureReport(reportId byte) ([]byte, error) {
	buf := make([]byte, d.reportFeatureLength+1)
	if d.reportWithId {
		buf[0] = reportId
	}

	rv, err := ioctl(d.extra.file.Fd(), uint(ioc(iocWrite|iocRead, 'H', 0x07, uint16(len(buf)))), uintptr(unsafe.Pointer(&buf[0])))
	if err != nil {
		return nil, err
	}

	start := 0
	if d.reportWithId {
		start++
		rv--
	}
	return buf[start : start+rv], nil
}

func (d *Device) setFeatureReport(reportId byte, data []byte) error {
	buf := append([]byte{reportId}, data...)
	_, err := ioctl(d.extra.file.Fd(), uint(ioc(iocWrite|iocRead, 'H', 0x06, uint16(len(buf)))), uintptr(unsafe.Pointer(&buf[0])))
	return err
}
