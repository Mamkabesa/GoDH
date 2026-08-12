/*
 * ports_test.go — unit tests for the "-p" port spec parser
 * (parsePortLists + makePortSpecs). Each case covers a CLI form:
 * explicit pairs, camera-only lists, ranges, and error inputs.
 */

package main

import "testing"

func TestPortParsing(t *testing.T) {
	cases := []struct {
		in      string
		want    []PortSpec
		wantErr bool
	}{
		{"8081", []PortSpec{{Local: 0, Remote: 8081}}, false},
		{"80-85", []PortSpec{{0, 80}, {0, 81}, {0, 82}, {0, 83}, {0, 84}, {0, 85}}, false},
		{"81,82,83", []PortSpec{{0, 81}, {0, 82}, {0, 83}}, false},
		{"8080:81", []PortSpec{{8080, 81}}, false},
		{"5080,5081,5082:80", []PortSpec{{5080, 80}, {5081, 80}, {5082, 80}}, false},
		{"5080,5081,5082:80,81,82", []PortSpec{{5080, 80}, {5081, 81}, {5082, 82}}, false},
		{"0:81", []PortSpec{{0, 81}}, false},
		{"8080-8082:80-82", []PortSpec{{8080, 80}, {8081, 81}, {8082, 82}}, false},
		{"8080:81,82", nil, true},
		{"80-85:0", nil, true},
		{"abc", nil, true},
	}
	for _, c := range cases {
		locals, remotes, err := parsePortLists(c.in)
		if err != nil {
			if c.wantErr {
				continue
			}
			t.Fatalf("%q: unexpected err %v", c.in, err)
		}
		specs, err := makePortSpecs(locals, remotes)
		if err != nil {
			if c.wantErr {
				continue
			}
			t.Fatalf("%q: makePortSpecs err %v", c.in, err)
		}
		if len(specs) != len(c.want) {
			t.Fatalf("%q: got %d specs, want %d", c.in, len(specs), len(c.want))
		}
		for i := range specs {
			if specs[i] != c.want[i] {
				t.Fatalf("%q: spec[%d]=%+v, want %+v", c.in, i, specs[i], c.want[i])
			}
		}
	}
}
