package classify

import (
	"os"
	"testing"

	"github.com/andreysheva/php2shell-doctor/internal/model"
	"github.com/andreysheva/php2shell-doctor/internal/vendordb"
)

func testDB(t *testing.T) *vendordb.DB {
	t.Helper()
	raw, err := os.ReadFile("../vendordb/vendordb.json")
	if err != nil {
		t.Fatal(err)
	}
	db, err := vendordb.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestClassifyUbuntuBackportNotFalsePositive(t *testing.T) {
	db := testDB(t)
	// THE canonical case: upstream 8.3.6 (below 8.3.36) but the Ubuntu
	// revision carries the backport. Must be PATCHED.
	inst := model.Install{
		Source: "distro-packages", Provenance: model.ProvDpkg, VendorID: "ubuntu",
		PackageName: "php8.3", PackageVersion: "8.3.6-0ubuntu0.24.04.13",
	}
	rep := Install(db, inst)
	if rep.Verdict != model.VerdictPatched {
		t.Fatalf("Ubuntu backport misclassified as %s (must be PATCHED)", rep.Verdict)
	}
}

func TestClassifyMatrix(t *testing.T) {
	db := testDB(t)
	cases := []struct {
		name string
		inst model.Install
		want model.Verdict
	}{
		{"old ubuntu revision", model.Install{
			Provenance: model.ProvDpkg, VendorID: "ubuntu", PackageName: "php8.3",
			PackageVersion: "8.3.6-0ubuntu0.24.04.12"}, model.VerdictVulnerable},
		{"debian fixed", model.Install{
			Provenance: model.ProvDpkg, VendorID: "debian", PackageName: "php8.2",
			PackageVersion: "8.2.35-1~deb12u1"}, model.VerdictPatched},
		{"debian vulnerable", model.Install{
			Provenance: model.ProvDpkg, VendorID: "debian", PackageName: "php8.2",
			PackageVersion: "8.2.32-1~deb12u1"}, model.VerdictVulnerable},
		{"sury vulnerable", model.Install{
			Provenance: model.ProvDpkg, VendorID: "sury", PackageName: "php8.2",
			PackageVersion: "8.2.24-1+ubuntu22.04.1+deb.sury.org+1"}, model.VerdictVulnerable},
		{"sury fixed", model.Install{
			Provenance: model.ProvDpkg, VendorID: "sury", PackageName: "php8.3",
			PackageVersion: "8.3.36-1+ubuntu24.04.1+deb.sury.org+1"}, model.VerdictPatched},
		{"redhat verify policy", model.Install{
			Provenance: model.ProvRpm, VendorID: "redhat-family", PackageName: "php",
			PackageVersion: "8.2.13-3.module_el9"}, model.VerdictVerifyVendor},
		{"unknown vendor below fixed", model.Install{
			Provenance: model.ProvDpkg, VendorID: "", PackageName: "php83",
			PackageVersion: "8.3.14-r0"}, model.VerdictVerifyVendor},
		{"standalone vulnerable", model.Install{
			Source: "PATH", Provenance: model.ProvStandalone, BinaryPath: "/opt/php/bin/php",
			VersionRaw: "8.3.6"}, model.VerdictVulnerable},
		{"standalone patched", model.Install{
			Source: "PATH", Provenance: model.ProvStandalone, BinaryPath: "/opt/php/bin/php",
			VersionRaw: "8.4.27"}, model.VerdictPatched},
		{"eol branch", model.Install{
			Source: "PATH", Provenance: model.ProvStandalone, BinaryPath: "/usr/bin/php7.4",
			VersionRaw: "7.4.33"}, model.VerdictEOLVulnerable},
		{"eol 8.1 distro", model.Install{
			Provenance: model.ProvDpkg, VendorID: "ubuntu", PackageName: "php8.1",
			PackageVersion: "8.1.2-1ubuntu2.22"}, model.VerdictVerifyVendor},
		{"partial image tag", model.Install{
			Source: "docker-image", ContainerImage: "php:8.3-apache",
			VersionRaw: "8.3.0", TagPartial: true}, model.VerdictPatchUnknownVer},
		{"exact vulnerable image", model.Install{
			Source: "docker-image", ContainerImage: "php:8.3.6-fpm",
			VersionRaw: "8.3.6"}, model.VerdictVulnerable},
		{"no version at all", model.Install{
			Source: "windows-registry"}, model.VerdictPatchUnknownVer},
	}
	for _, c := range cases {
		rep := Install(db, c.inst)
		if rep.Verdict != c.want {
			t.Errorf("%s: verdict = %s (reason: %s) want %s", c.name, rep.Verdict, rep.Reason, c.want)
		}
	}
}

func TestClassifyModPHPFinding(t *testing.T) {
	db := testDB(t)
	rep := Install(db, model.Install{
		Source: "apache-mod-php", Provenance: model.ProvStandalone,
		VersionRaw: "8.3.6", SAPIs: []model.SAPI{model.SAPIApacheMod},
	})
	found := false
	for _, f := range rep.Findings {
		if f.Code == "SAPI-MODPHP" {
			found = true
		}
	}
	if !found || rep.Verdict != model.VerdictVulnerable {
		t.Fatalf("mod_php finding missing or verdict wrong: %v %s", found, rep.Verdict)
	}
}

func TestPerCVEStatuses(t *testing.T) {
	db := testDB(t)
	rep := Install(db, model.Install{
		Provenance: model.ProvDpkg, VendorID: "debian", PackageName: "php8.2",
		PackageVersion: "8.2.35-1~deb12u1"})
	for _, cve := range FixCVEs {
		if rep.PerCVE[cve] != "fixed" {
			t.Fatalf("PerCVE[%s] = %s want fixed", cve, rep.PerCVE[cve])
		}
	}
}
