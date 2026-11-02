package main

// archiveBuildArgv is the exec that runs a consumer's build command. The
// command reaches the inner shell as its own script ("$1"), never spliced
// into cicd's: wrapped in "( %s )" a trailing "# comment" swallowed the
// closing paren and a heredoc lost its terminator, so cicd's own syntax
// error replaced the consumer's build. Output and exit code land in files
// so a non-zero exit never aborts the Dagger exec.
func archiveBuildArgv(cmd, outPath, errPath, exitPath string) []string {
	return []string{"sh", "-c", `sh -c "$1" > "$2" 2> "$3"; echo $? > "$4"`, "build-archive", cmd, outPath, errPath, exitPath}
}
