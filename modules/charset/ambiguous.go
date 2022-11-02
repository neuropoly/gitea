// This file is generated by modules/charset/ambiguous/generate.go DO NOT EDIT
// Copyright 2022 The Gitea Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package charset

import (
	"sort"
	"strings"
	"unicode"

	"code.gitea.io/gitea/modules/translation"
)

// AmbiguousTablesForLocale provides the table of ambiguous characters for this locale.
func AmbiguousTablesForLocale(locale translation.Locale) []*AmbiguousTable {
	key := locale.Language()
	var table *AmbiguousTable
	var ok bool
	for len(key) > 0 {
		if table, ok = AmbiguousCharacters[key]; ok {
			break
		}
		idx := strings.LastIndexAny(key, "-_")
		if idx < 0 {
			key = ""
		} else {
			key = key[:idx]
		}
	}
	if table == nil {
		table = AmbiguousCharacters["_default"]
	}

	return []*AmbiguousTable{
		table,
		AmbiguousCharacters["_common"],
	}
}

func isAmbiguous(r rune, confusableTo *rune, tables ...*AmbiguousTable) bool {
	for _, table := range tables {
		if !unicode.Is(table.RangeTable, r) {
			continue
		}
		i := sort.Search(len(table.Confusable), func(i int) bool {
			return table.Confusable[i] >= r
		})
		(*confusableTo) = table.With[i]
		return true
	}
	return false
}