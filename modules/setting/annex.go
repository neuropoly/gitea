// Copyright 2019 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package setting

import (
	"code.gitea.io/gitea/modules/log"
)

// Annex represents the configuration for git-annex
var Annex = struct {
	Enabled bool `ini:"ENABLED"`
}{}

func newAnnex() {
	sec := Cfg.Section("annex")
	if err := sec.MapTo(&Annex); err != nil {
		log.Fatal("Failed to map Annex settings: %v", err)
	}
}
