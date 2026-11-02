package risk.azure

import rego.v1

# Only check top-level resources (two path segments: "Microsoft.Foo/bars").
# Sub-resources ("Microsoft.Foo/bars/baz") inherit tags from parent and
# typically do not carry their own tags.
top_level_resource(res) if {
	parts := split(res.type, "/")
	count(parts) == 2
}

required_tags := ["environment", "owner", "project"]

# TAG-001 / TAG-002 / TAG-003: Required tags missing on top-level resources.
violation contains finding if {
	arm_template
	some res in input.resources
	top_level_resource(res)
	some tag in required_tags
	not res.tags[tag]
	finding := {
		"msg": sprintf("TAG-%s: Resource %q is missing the required '%s' tag", [tag_id(tag), res.name, tag]),
		"id": sprintf("TAG-%s", [tag_id(tag)]),
		"title": sprintf("Resource missing '%s' tag", [tag]),
		"severity": "low",
		"category": "ops",
		"resource": res.name,
		"remediation": sprintf("Add a '%s' tag that identifies the %s for this resource", [tag, tag]),
	}
}

tag_id("environment") := "001"

tag_id("owner") := "002"

tag_id("project") := "003"

# conftest reads deny for failure reporting; derive from violation so OPA tests remain unchanged
deny contains msg if {
	some f in violation
	msg := f.msg
}
