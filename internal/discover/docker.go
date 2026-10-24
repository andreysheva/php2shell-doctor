package discover

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/php2shell-doctor/php2shell-doctor/internal/execx"
	"github.com/php2shell-doctor/php2shell-doctor/internal/model"
)

var dockerTagVerRe = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

// scanDocker inventories PHP/FrankenPHP containers and images via the
// docker CLI. With DockerExec, runs `php -v` inside running containers
// (read-only) to get exact runtime versions — tags alone lie.
func scanDocker(opts Options) ([]model.Install, error) {
	if _, ok := execx.LookPath("docker"); !ok {
		return nil, fmt.Errorf("docker CLI not found")
	}
	var out []model.Install
	// Running containers
	r := execx.Run(30e9, "docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}")
	if r.Err != nil {
		return nil, fmt.Errorf("docker ps failed: %v", r.Stderr)
	}
	for _, line := range strings.Split(r.Stdout, "\n") {
		f := strings.Split(strings.TrimSpace(line), "\t")
		if len(f) != 3 {
			continue
		}
		cid, image, name := f[0], f[1], f[2]
		if !phpImage(image) {
			continue
		}
		inst := model.Install{
			Source:         "docker-container",
			ContainerID:    cid,
			ContainerImage: image,
			PackageName:    image,
			PackageVersion: image,
			Note:           "running container " + name,
		}
		if v, exact, ok := versionFromImageTag(image); ok {
			inst.VersionRaw = v
			if !exact {
				inst.TagPartial = true
			}
		}
		if opts.DockerExec {
			vr := execx.Run(30e9, "docker", "exec", cid, "php", "-v")
			if vr.Err == nil {
				var tmp model.Install
				parsePHPVersionBanner(&tmp, vr.Stdout)
				if tmp.VersionRaw != "" {
					inst.VersionRaw = tmp.VersionRaw
					inst.Note = appendNote(inst.Note, "version from in-container php -v")
				}
			}
			fv := execx.Run(30e9, "docker", "exec", cid, "frankenphp", "php-v")
			if fv.Err == nil && inst.VersionRaw == "" {
				var tmp model.Install
				parsePHPVersionBanner(&tmp, fv.Stdout)
				inst.VersionRaw = tmp.VersionRaw
				inst.SAPIs = []model.SAPI{model.SAPIFranken}
			}
		}
		out = append(out, inst)
	}
	// Local images (the ones you might deploy next). Images that already
	// run as containers are covered by the container rows above — listing
	// both would duplicate every deployment in the report.
	runningImage := map[string]bool{}
	for _, i := range out {
		if i.ContainerID != "" {
			runningImage[i.ContainerImage] = true
		}
	}
	ri := execx.Run(30e9, "docker", "images", "--format", "{{.Repository}}:{{.Tag}}")
	if ri.Err == nil {
		for _, line := range strings.Split(ri.Stdout, "\n") {
			ref := strings.TrimSpace(line)
			if ref == "" || !phpImage(ref) || runningImage[ref] {
				continue
			}
			inst := model.Install{
				Source:         "docker-image",
				ContainerImage: ref,
				PackageName:    ref,
				PackageVersion: ref,
			}
			if v, exact, ok := versionFromImageTag(ref); ok {
				inst.VersionRaw = v
				inst.TagPartial = !exact
				inst.Note = "version from image tag only — rebuilt/custom images must be verified with --docker-exec"
			}
			out = append(out, inst)
		}
	}
	return out, nil
}

func phpImage(ref string) bool {
	l := strings.ToLower(ref)
	return strings.HasPrefix(l, "php:") || strings.HasPrefix(l, "frankenphp") ||
		strings.Contains(l, "/php") || strings.Contains(l, "wordpress") ||
		strings.Contains(l, "nextcloud") || strings.Contains(l, "laravel") ||
		strings.Contains(l, "dunglas/frankenphp")
}

// versionFromImageTag extracts a PHP version from an image tag.
// The bool return is true when the tag carries an explicit patch version
// ("8.3.6-fpm"); minor-only tags ("8.3-apache") yield a floor version
// and TagPartial must be set by the caller.
func versionFromImageTag(ref string) (string, bool, bool) {
	// take the tag part (after the last colon)
	tag := ref
	if i := strings.LastIndexByte(tag, ':'); i >= 0 {
		tag = tag[i+1:]
	}
	m := dockerTagVerRe.FindStringSubmatch(tag)
	if m == nil {
		return "", false, false
	}
	exact := m[3] != ""
	v := m[1] + "." + m[2] + "." + m[3]
	if !exact {
		v = v + "0"
	}
	return v, exact, true
}
