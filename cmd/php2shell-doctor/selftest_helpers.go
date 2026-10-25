package main

import "github.com/andreysheva/php2shell-doctor/internal/pkgver"

// pkgCompare validates the dpkg comparator on the Debian bookworm case.
func pkgCompare(_ string) bool {
	return pkgver.DpkgCompare("8.2.32-1~deb12u1", "8.2.35-1~deb12u1") < 0
}
