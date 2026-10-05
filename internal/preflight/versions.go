package preflight

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const v2rayAPackageAction = "Install the companion v2raya package version 2.5.8 or later with its matching v2raya_core; the older firmware-feed v2raya package is incompatible."

type releaseVersion struct {
	numbers    [3]uint64
	prerelease string
}

var releaseVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func parseReleaseVersion(token string) (releaseVersion, error) {
	var out releaseVersion
	parts := releaseVersionPattern.FindStringSubmatch(strings.TrimPrefix(token, "v"))
	if parts == nil {
		return out, errors.New("unrecognized release version")
	}
	for i := range out.numbers {
		n, err := strconv.ParseUint(parts[i+1], 10, 64)
		if err != nil {
			return releaseVersion{}, errors.New("invalid release version number")
		}
		out.numbers[i] = n
	}
	out.prerelease = parts[4]
	for _, label := range strings.Split(out.prerelease, ".") {
		if len(label) < 2 || label[0] != '0' {
			continue
		}
		if strings.IndexFunc(label, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
			return releaseVersion{}, errors.New("invalid prerelease version number")
		}
	}
	return out, nil
}

func (v releaseVersion) meetsMinimum() bool {
	minimum := [3]uint64{2, 5, 8}
	for i := range minimum {
		if v.numbers[i] != minimum[i] {
			return v.numbers[i] > minimum[i]
		}
	}
	return v.prerelease == ""
}

// Verified upstream 2.5.8 prints a bare release token for --version.
func managerVersion(line string) (releaseVersion, error) {
	version, err := parseReleaseVersion(strings.TrimSpace(line))
	if err != nil {
		return releaseVersion{}, errors.New("v2rayA did not report a supported semantic version; version 2.5.8 or later is required")
	}
	if !version.meetsMinimum() {
		return releaseVersion{}, errors.New("v2rayA is older than the required 2.5.8 release")
	}
	return version, nil
}

// Verified upstream core prints "V2RAYA_CORE 2.5.8 (based on xray-core ...)".
// The Xray version in the remaining metadata is a different version scheme.
func coreVersion(line string) (releaseVersion, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "V2RAYA_CORE" {
		return releaseVersion{}, errors.New("v2raya_core did not report a V2RAYA_CORE release banner")
	}
	version, err := parseReleaseVersion(fields[1])
	if err != nil {
		return releaseVersion{}, errors.New("v2raya_core did not report a supported semantic version")
	}
	return version, nil
}

func runVersionCheck(ctx context.Context, opts Options, name string, args []string, parse func(string) (releaseVersion, error)) (releaseVersion, error) {
	if err := ctx.Err(); err != nil {
		return releaseVersion{}, err
	}
	path, err := opts.Runner.LookPath(name)
	if err != nil {
		return releaseVersion{}, fmt.Errorf("executable %s is missing or not executable", name)
	}
	checkCtx, cancel := context.WithTimeout(ctx, opts.CommandTimeout)
	defer cancel()
	line, err := opts.Runner.Version(checkCtx, path, args...)
	if err != nil {
		if checkCtx.Err() != nil {
			return releaseVersion{}, fmt.Errorf("%s version check: %w", name, checkCtx.Err())
		}
		// Neither process output nor a runner's private diagnostic is safe to
		// embed into the public report.
		return releaseVersion{}, fmt.Errorf("%s version command failed", name)
	}
	return parse(line)
}
