package linuxitems

/*
   Simple helper functions for enabling/disabling IPv6 on a Linux interface through
   sysctl kernel parameters, by reading/writing the corresponding files under /proc/sys.

   TODO: ../../nireconciler/linuxitems/sysctl.go already has an implementation
   for handling sysctl kernel parameter although that is more complicated since
   it's part of the dependency graph. Should we use that instead ?
*/

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// kernelHasIPv6 verifies if IPv6 is enabled in the kernel. If it returns an
// error then the boolean value should be ignored as it can't actually say
// if IPv6 support is present or not in the kernel.
func kernelHasIPv6() (bool, error) {
	ipv6DisablePath := "/proc/sys/net/ipv6/conf/all/disable_ipv6"
	if _, err := os.Stat(ipv6DisablePath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("can't stat '%s': %w", ipv6DisablePath, err)
	}

	return true, nil
}

// setSysctlInt sets a `sysctl` kernel parameter by writing to the corresponding
// file under `/proc/sys`.
func setSysctlInt(key string, val int) error {
	path := filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", string(filepath.Separator)))
	data := []byte(strconv.Itoa(val))

	// NOTE: We're not trying to set any file permissions since for "files"
	// under `/proc/sys` those will be ignored anyway.
	if err := os.WriteFile(path, data, 0); err != nil {
		return fmt.Errorf("setSysctlInt(%s, %d): %w", key, val, err)
	}

	return nil
}

// getSysctlInt reads a `sysctl` kernel parameter by reading the corresponding
// file under `/proc/sys`.
func getSysctlInt(key string) (int, error) {
	path := filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", string(filepath.Separator)))
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("getSysctlInt(%s): %w", key, err)
	}

	// Also trim `0x0` since unicode.IsSpace doesn't include it.
	val, err := strconv.Atoi(strings.TrimSpace(strings.Trim(string(data), "\x00")))
	if err != nil {
		return 0, fmt.Errorf("getSysctlInt(%s) invalid integer value '%s': %w",
			key, string(data), err)
	}

	return val, nil
}

// confIntfIPv6 enables or disables IPv6 support for a specific interface through
// the `net.ipv6.conf.<intf_name>.disable_ipv6` key.
func confIntfIPv6(intf string, disabled bool) error {
	key := fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", intf)
	curr, err := getSysctlInt(key)
	if err != nil {
		return fmt.Errorf("confIntfIPv6(%s, %t) failed to get current IPv6 status: %w",
			intf, disabled, err)
	}

	want := 0
	if disabled {
		want = 1
	}

	if curr == want {
		// Already set to the wanted value.
		return nil
	}

	if err := setSysctlInt(key, want); err != nil {
		return fmt.Errorf("confIntfIPv6(%s, %t) failed to set IPv6 status: %w",
			intf, disabled, err)
	}

	got, err := getSysctlInt(key)
	if err != nil {
		return fmt.Errorf("confIntfIPv6(%s, %t) failed to get updated IPv6 status: %w",
			intf, disabled, err)
	}

	if got != want {
		return fmt.Errorf("sysctl value not set correctly: got %d, want %d",
			got, want)
	}

	return nil
}
