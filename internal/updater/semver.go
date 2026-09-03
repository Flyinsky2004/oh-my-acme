package updater

import (
	"fmt"
	"strings"
)

type semVersion struct {
	major string
	minor string
	patch string
	pre   []preIdentifier
}

type preIdentifier struct {
	value   string
	numeric bool
}

func parseSemVer(value string) (semVersion, error) {
	if strings.HasPrefix(value, "v") {
		value = value[1:]
	}
	if value == "" {
		return semVersion{}, errorsf("empty version")
	}
	withoutBuild, build, hasBuild := strings.Cut(value, "+")
	if hasBuild && !validIdentifiers(build, false) {
		return semVersion{}, errorsf("invalid build metadata")
	}
	core, prerelease, hasPrerelease := strings.Cut(withoutBuild, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semVersion{}, errorsf("version core must contain major.minor.patch")
	}
	for _, part := range parts {
		if err := validateNumber(part); err != nil {
			return semVersion{}, err
		}
	}
	version := semVersion{major: parts[0], minor: parts[1], patch: parts[2]}
	if !hasPrerelease {
		return version, nil
	}
	pre, err := parsePrerelease(prerelease)
	if err != nil {
		return semVersion{}, err
	}
	version.pre = pre
	return version, nil
}

func (v semVersion) stable() bool {
	return len(v.pre) == 0
}

func (v semVersion) compare(other semVersion) int {
	if result := compareNumber(v.major, other.major); result != 0 {
		return result
	}
	if result := compareNumber(v.minor, other.minor); result != 0 {
		return result
	}
	if result := compareNumber(v.patch, other.patch); result != 0 {
		return result
	}
	if len(v.pre) == 0 && len(other.pre) == 0 {
		return 0
	}
	if len(v.pre) == 0 {
		return 1
	}
	if len(other.pre) == 0 {
		return -1
	}
	limit := len(v.pre)
	if len(other.pre) < limit {
		limit = len(other.pre)
	}
	for i := 0; i < limit; i++ {
		left, right := v.pre[i], other.pre[i]
		if left.numeric && right.numeric {
			if result := compareNumber(left.value, right.value); result != 0 {
				return result
			}
			continue
		}
		if left.numeric != right.numeric {
			if left.numeric {
				return -1
			}
			return 1
		}
		if left.value < right.value {
			return -1
		}
		if left.value > right.value {
			return 1
		}
	}
	if len(v.pre) < len(other.pre) {
		return -1
	}
	if len(v.pre) > len(other.pre) {
		return 1
	}
	return 0
}

func validateNumber(value string) error {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return errorsf("numeric identifiers must not contain leading zeroes")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return errorsf("numeric identifiers must contain only digits")
		}
	}
	return nil
}

func parsePrerelease(value string) ([]preIdentifier, error) {
	if !validIdentifiers(value, true) {
		return nil, errorsf("invalid prerelease")
	}
	parts := strings.Split(value, ".")
	identifiers := make([]preIdentifier, len(parts))
	for i, part := range parts {
		identifiers[i] = preIdentifier{value: part, numeric: isNumeric(part)}
	}
	return identifiers, nil
}

func validIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	if value == "" {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" {
			return false
		}
		for _, character := range part {
			if !((character >= '0' && character <= '9') || (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || character == '-') {
				return false
			}
		}
		if rejectNumericLeadingZero && isNumeric(part) && len(part) > 1 && part[0] == '0' {
			return false
		}
	}
	return true
}

func isNumeric(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return value != ""
}

func compareNumber(left, right string) int {
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func errorsf(message string) error {
	return fmt.Errorf("invalid SemVer: %s", message)
}
