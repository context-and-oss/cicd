package main

import (
	"strings"
	"testing"
)

// ok is a run that agrees with itself: --app container, a source tree to build,
// a real port and a real mode. Each test below changes one thing.
func ok() (string, appInputs) {
	return appContainer, appInputs{HasSrc: true, Port: 8080, Mode: "baseline"}
}

func TestValidateAppAcceptsEachShapeWithItsOwnSource(t *testing.T) {
	for _, tc := range []struct {
		app string
		in  appInputs
	}{
		{appURL, appInputs{Target: "https://staging.example.com/app", Port: 8080, Mode: "baseline"}},
		{appService, appInputs{HasService: true, Port: 5000, Mode: "api"}},
		{appContainer, appInputs{HasSrc: true, Port: 8080, Mode: "full"}},
	} {
		if err := validateApp(tc.app, tc.in); err != nil {
			t.Errorf("validateApp(%q, %+v): %v", tc.app, tc.in, err)
		}
	}
}

// TestValidateAppRefusesAShapeItDoesNotKnow is the regression guard for the
// missing default arm. url is the shape that needs the least from the caller,
// so a fall-through would accept a typo and scan whatever --target happened to
// hold — or nothing.
func TestValidateAppRefusesAShapeItDoesNotKnow(t *testing.T) {
	for _, app := range []string{"", "URL", "Container", "docker", "compose", "true"} {
		in := appInputs{Target: "https://x", HasService: true, HasSrc: true, Port: 8080, Mode: "baseline"}
		err := validateApp(app, in)
		if err == nil {
			t.Errorf("validateApp(%q) accepted a shape cicd does not recognise", app)
			continue
		}
		if !strings.Contains(err.Error(), "url|service|container") {
			t.Errorf("validateApp(%q) = %q, want the three shapes named", app, err)
		}
	}
}

// TestValidateAppRefusesAShapeWithNoSource. Each of these would reach ScanWeb
// as "no target", which is already refused there — but the message would name
// three parameters instead of the one the consumer chose.
func TestValidateAppRefusesAShapeWithNoSource(t *testing.T) {
	for _, tc := range []struct {
		name, app, want string
		in              appInputs
	}{
		{"url with no target", appURL, "--target", appInputs{Port: 8080, Mode: "baseline"}},
		{"url with a blank target", appURL, "--target", appInputs{Target: "   ", Port: 8080, Mode: "baseline"}},
		{"service with nothing bound", appService, "--service", appInputs{Port: 8080, Mode: "baseline"}},
		{"container with no source", appContainer, "--src", appInputs{Port: 8080, Mode: "baseline"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateApp(tc.app, tc.in)
			if err == nil {
				t.Fatalf("validateApp(%q, %+v) accepted a shape with no source", tc.app, tc.in)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %s", err, tc.want)
			}
		})
	}
}

// TestValidateAppRefusesASecondSource keeps the composite's selector and
// ScanWeb's exactly-one rule from disagreeing: whichever one of them notices,
// the run must not proceed.
func TestValidateAppRefusesASecondSource(t *testing.T) {
	for _, tc := range []struct {
		name, app string
		in        appInputs
	}{
		{"url and service", appURL, appInputs{Target: "https://x", HasService: true, Port: 8080, Mode: "baseline"}},
		{"service and target", appService, appInputs{Target: "https://x", HasService: true, Port: 8080, Mode: "baseline"}},
		{"container and target", appContainer, appInputs{Target: "https://x", HasSrc: true, Port: 8080, Mode: "baseline"}},
		{"container and service", appContainer, appInputs{HasService: true, HasSrc: true, Port: 8080, Mode: "baseline"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateApp(tc.app, tc.in); err == nil {
				t.Errorf("validateApp(%q, %+v) accepted two sources", tc.app, tc.in)
			}
		})
	}
}

// TestValidateAppRefusesASourceTreeItWouldNotBuild. --src reaching a shape
// that builds nothing is an input silently ignored, and the run then reads as
// a scan of the code in this commit when it is a scan of whatever the consumer
// pointed at. ScanWeb applies the same rule to an API document supplied
// outside --mode api.
func TestValidateAppRefusesASourceTreeItWouldNotBuild(t *testing.T) {
	for _, tc := range []struct{ name, app string }{
		{"url", appURL},
		{"service", appService},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := appInputs{Target: "https://x", HasSrc: true, Port: 8080, Mode: "baseline"}
			if tc.app == appService {
				in = appInputs{HasService: true, HasSrc: true, Port: 8080, Mode: "baseline"}
			}
			err := validateApp(tc.app, in)
			if err == nil {
				t.Fatalf("validateApp(%q) accepted a --src it would never build", tc.app)
			}
			if !strings.Contains(err.Error(), "--src") {
				t.Errorf("error = %q, want it to name --src", err)
			}
		})
	}
}

// TestValidateAppRefusesTheValuesTheClientWouldDrop.
//
// The whole reason these two are checked here: Dagger's generated Go client
// drops an optional argument holding its zero value, so neither an empty mode
// nor a zero port ever reaches ScanWeb to be refused there. They arrive as
// ScanWeb's defaults instead — the weakest scan, and port 8080.
func TestValidateAppRefusesTheValuesTheClientWouldDrop(t *testing.T) {
	for _, mode := range []string{"", "   "} {
		app, in := ok()
		in.Mode = mode
		err := validateApp(app, in)
		if err == nil {
			t.Fatalf("validateApp accepted mode %q, which is dropped and becomes baseline", mode)
		}
		if !strings.Contains(err.Error(), "weakest scan") {
			t.Errorf("error = %q, want it to say what an empty mode silently becomes", err)
		}
	}

	for _, port := range []int{0, -1, 70000} {
		for _, app := range []string{appService, appContainer} {
			in := appInputs{HasService: app == appService, HasSrc: app == appContainer, Port: port, Mode: "baseline"}
			if err := validateApp(app, in); err == nil {
				t.Errorf("validateApp(%q) accepted port %d", app, port)
			}
		}
	}
}

// TestValidateAppIgnoresThePortTheURLShapeCarriesItself. --target holds its own
// port, so checking a --port nobody reads would refuse a valid run over a
// parameter that has no effect.
func TestValidateAppIgnoresThePortTheURLShapeCarriesItself(t *testing.T) {
	for _, port := range []int{0, -1, 70000} {
		in := appInputs{Target: "https://staging.example.com:8443/app", Port: port, Mode: "baseline"}
		if err := validateApp(appURL, in); err != nil {
			t.Errorf("validateApp(url) with port %d: %v", port, err)
		}
	}
}

// TestValidateAppPassesAnUnknownModeThrough. The mode set lives in
// src/security/webmode.go and is refused there; a second copy here would be a
// second thing to keep in step, and the drift would show up as a mode this
// composite rejects and the module accepts. Only the empty string is checked
// here, because only the empty string never arrives.
func TestValidateAppPassesAnUnknownModeThrough(t *testing.T) {
	app, in := ok()
	in.Mode = "quick"
	if err := validateApp(app, in); err != nil {
		t.Errorf("validateApp rejected mode %q locally; ScanWeb owns that refusal: %v", in.Mode, err)
	}
}
