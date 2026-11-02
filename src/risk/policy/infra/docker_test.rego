package risk.docker_test

import rego.v1

import data.risk.docker

test_no_user_instruction_fires if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["golang:1.24-alpine"]},
		{"Cmd": "run", "Value": ["apk add --no-cache curl"]},
	]
	some f in findings
	f.id == "DOCKER-001"
}

test_user_instruction_suppresses_docker001 if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["golang:1.24-alpine"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	root_violations := [f | f := findings[_]; f.id == "DOCKER-001"]
	count(root_violations) == 0
}

test_latest_tag_fires if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["ubuntu:latest"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	some f in findings
	f.id == "DOCKER-002"
}

test_no_tag_fires if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["ubuntu"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	some f in findings
	f.id == "DOCKER-002"
}

test_pinned_tag_passes if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["ubuntu:22.04"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	count(findings) == 0
}

test_digest_pinned_passes if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["ubuntu@sha256:abc123"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	count(findings) == 0
}

test_scratch_not_flagged if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["scratch"]},
	]
	pin_violations := [f | f := findings[_]; f.id == "DOCKER-002"]
	count(pin_violations) == 0
}

test_registry_with_port_no_tag_fires if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["registry.example:5000/myimage"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	some f in findings
	f.id == "DOCKER-002"
}

test_registry_with_port_latest_tag_fires if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["registry.example:5000/myimage:latest"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	some f in findings
	f.id == "DOCKER-002"
}

test_registry_with_port_pinned_tag_passes if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["registry.example:5000/myimage:1.2.3"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	count(findings) == 0
}

test_registry_with_port_digest_pinned_passes if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["registry.example:5000/myimage@sha256:abc123"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	count(findings) == 0
}

# The conftest Dockerfile parser hands the whole argument list of a
# FROM instruction to instr.Value, so a multi-stage `FROM <image> AS <alias>`
# arrives as ["<image>", "AS", "<alias>"]. Only the first token is a base
# image; iterating the list treated "AS" and the alias as untagged images and
# produced two false MEDIUM DOCKER-002 findings per stage.
test_multistage_alias_tokens_are_not_treated_as_images if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["golang:1.26-alpine", "AS", "builder"]},
		{"Cmd": "from", "Value": ["alpine:3.22", "AS", "runtime"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	count(findings) == 0
}

test_multistage_unpinned_image_still_fires_once if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["golang", "AS", "builder"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	pin_violations := [f | f := findings[_]; f.id == "DOCKER-002"]
	count(pin_violations) == 1
	pin_violations[0].resource == "Dockerfile FROM golang"
}

# Dockerfile keywords are case-insensitive, so the alias keyword may arrive as
# "as". It must be ignored on the same grounds as "AS".
test_multistage_lowercase_as_alias_is_not_an_image if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["golang:1.26-alpine", "as", "builder"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	count(findings) == 0
}

test_multistage_digest_pinned_with_alias_passes if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["golang@sha256:abc123", "AS", "builder"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	count(findings) == 0
}

test_multistage_scratch_with_alias_passes if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["scratch", "AS", "final"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	count(findings) == 0
}

# Each FROM is judged on its own image token, so an unpinned later stage is
# still caught even when the first stage is pinned.
test_multistage_later_unpinned_stage_is_caught if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["golang:1.26-alpine", "AS", "builder"]},
		{"Cmd": "from", "Value": ["alpine", "AS", "runtime"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	pin_violations := [f | f := findings[_]; f.id == "DOCKER-002"]
	count(pin_violations) == 1
	pin_violations[0].resource == "Dockerfile FROM alpine"
}

# A FROM may use a previously declared stage as its base. The stage name is not
# an image reference and therefore must not be asked to carry a tag or digest.
test_previous_stage_alias_is_not_an_unpinned_image if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["alpine:3.22", "AS", "base"]},
		{"Cmd": "from", "Value": ["base", "AS", "final"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	count(findings) == 0
}

# Docker stage names are case-insensitive by design. A differently-cased use
# must still resolve to the earlier stage rather than look like a new image.
test_previous_stage_alias_match_is_case_insensitive if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["alpine:3.22", "AS", "BuildBase"]},
		{"Cmd": "from", "Value": ["buildbase", "AS", "final"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	count(findings) == 0
}

# The originating registry image is still judged. Reusing its stage must not
# duplicate that finding, so an unpinned origin produces exactly one result.
test_unpinned_origin_reused_by_alias_fires_once if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["alpine", "AS", "base"]},
		{"Cmd": "from", "Value": ["base", "AS", "final"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	pin_violations := [f | f := findings[_]; f.id == "DOCKER-002"]
	count(pin_violations) == 1
	pin_violations[0].resource == "Dockerfile FROM alpine"
}

test_stage_alias_chain_is_not_reported if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["alpine:3.22", "AS", "base"]},
		{"Cmd": "from", "Value": ["base", "AS", "development"]},
		{"Cmd": "from", "Value": ["development", "AS", "final"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	count(findings) == 0
}

# Only an earlier declaration is a stage source. A later stage named `base`
# cannot retroactively change Docker's interpretation of the first FROM.
test_future_alias_does_not_excuse_unpinned_image if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["base"]},
		{"Cmd": "from", "Value": ["alpine:3.22", "AS", "base"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	pin_violations := [f | f := findings[_]; f.id == "DOCKER-002"]
	count(pin_violations) == 1
	pin_violations[0].resource == "Dockerfile FROM base"
}

test_unrelated_untagged_image_still_fires if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": ["alpine:3.22", "AS", "base"]},
		{"Cmd": "from", "Value": ["ubuntu", "AS", "final"]},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	pin_violations := [f | f := findings[_]; f.id == "DOCKER-002"]
	count(pin_violations) == 1
	pin_violations[0].resource == "Dockerfile FROM ubuntu"
}

# Defensive: a FROM with no argument tokens carries no image to judge, so
# DOCKER-002 must stay silent rather than error on an absent Value[0].
test_from_without_arguments_does_not_fire if {
	findings := docker.violation with input as [
		{"Cmd": "from", "Value": []},
		{"Cmd": "user", "Value": ["appuser"]},
	]
	count(findings) == 0
}
