/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package spdx_test

import (
	"fmt"

	"chainguard.dev/license/spdx"
)

// Normalize maps a classifier's license name onto SPDX, reporting the three
// outcomes a caller has to handle.
func ExampleNormalize() {
	for _, name := range []string{"Apache-2.0", "BSD-0-Clause", "LGPL-3.0", "Commons-Clause"} {
		r := spdx.Normalize(name)
		switch {
		case r.NeedsGrant():
			fmt.Printf("%-14s -> %s or %s (grant undecided)\n", name, r.Only, r.OrLater)
		case r.ID != "":
			fmt.Printf("%-14s -> %s\n", name, r.ID)
		default:
			fmt.Printf("%-14s -> LicenseRef-%s\n", name, r.Ref)
		}
	}
	// Output:
	// Apache-2.0     -> Apache-2.0
	// BSD-0-Clause   -> 0BSD
	// LGPL-3.0       -> LGPL-3.0-only or LGPL-3.0-or-later (grant undecided)
	// Commons-Clause -> LicenseRef-Commons-Clause
}

// FromText resolves the prose and URLs that ecosystem manifests carry.
func ExampleFromText() {
	for _, s := range []string{"The Apache Software License, Version 2.0", "https://www.eclipse.org/legal/epl-2.0/", "GPL"} {
		if id, ok := spdx.FromText(s); ok {
			fmt.Printf("%q -> %s\n", s, id)
		} else {
			fmt.Printf("%q -> unresolved\n", s)
		}
	}
	// Output:
	// "The Apache Software License, Version 2.0" -> Apache-2.0
	// "https://www.eclipse.org/legal/epl-2.0/" -> EPL-2.0
	// "GPL" -> unresolved
}

// Tag reads the SPDX-License-Identifier convention, which the classifier does
// not recognize at all.
func ExampleTag() {
	id, ok := spdx.Tag("/* SPDX-License-Identifier: LGPL-2.1-or-later */")
	fmt.Println(id, ok)
	// Output: LGPL-2.1-or-later true
}
