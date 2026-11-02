package risk.docker

import rego.v1

# DOCKER-001: No USER instruction — container runs as root by default
violation contains finding if {
	is_array(input) # Dockerfile input is an array of instructions
	not any_user_instruction
	finding := {
		"msg": "DOCKER-001: No USER instruction — container runs as root by default",
		"id": "DOCKER-001",
		"title": "Container runs as root",
		"severity": "high",
		"category": "ops",
		"resource": "Dockerfile",
		"remediation": "Add USER <username> before ENTRYPOINT/CMD to run as a non-root user",
	}
}

any_user_instruction if {
	some instr in input
	lower(instr.Cmd) == "user"
}

# DOCKER-002: Base image not version-pinned (no tag or :latest)
violation contains finding if {
	is_array(input) # Dockerfile input is an array of instructions
	some instr_index, instr in input
	lower(instr.Cmd) == "from"
	count(instr.Value) > 0
	image := instr.Value[0]
	image != "scratch"
	not contains(image, "@sha256:")
	not previous_stage_alias(image, instr_index)
	unpinned(image)
	finding := {
		"msg": sprintf("DOCKER-002: Base image %q is not version-pinned", [image]),
		"id": "DOCKER-002",
		"title": "Base image not version-pinned",
		"severity": "medium",
		"category": "ops",
		"resource": sprintf("Dockerfile FROM %s", [image]),
		"remediation": "Pin to a specific version tag or digest (e.g. golang:1.24-alpine, not golang:latest)",
	}
}

# A later FROM may derive from a stage declared earlier in the same Dockerfile.
# That token names an already-resolved build stage, not a registry image, so it
# has no tag or digest of its own for DOCKER-002 to judge. Docker resolves stage
# names case-insensitively and only against stages already declared; keeping the
# index comparison here means a future `AS base` cannot excuse an earlier real
# `FROM base`, which Docker would still try to pull as base:latest.
previous_stage_alias(image, current_index) if {
	some prior_index, prior in input
	prior_index < current_index
	lower(prior.Cmd) == "from"
	count(prior.Value) >= 3
	lower(prior.Value[1]) == "as"
	lower(prior.Value[2]) == lower(image)
}

unpinned(image) if {
	# Extract image name (after the last /)
	# registry.io:5000/myimage -> myimage
	# myimage -> myimage
	parts := split(image, "/")
	image_name := parts[count(parts)-1]
	not contains(image_name, ":")
}

unpinned(image) if {
	# Extract image name and check if tag is "latest"
	# registry.io:5000/myimage:latest -> image_name=myimage:latest, tag=latest
	# ubuntu:latest -> image_name=ubuntu:latest, tag=latest
	parts := split(image, "/")
	image_name := parts[count(parts)-1]
	tag_parts := split(image_name, ":")
	count(tag_parts) > 1
	tag_parts[count(tag_parts)-1] == "latest"
}

# conftest reads deny for failure reporting; derive from violation so OPA tests remain unchanged
deny contains msg if {
	some f in violation
	msg := f.msg
}
