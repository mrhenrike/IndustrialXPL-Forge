class SearchEngine:
    """Multilingual module search engine."""

    def __init__(self, modules: list[str]) -> None:
        self.modules = modules
        self._norm_cache: dict[str, str] = {}

    def _norm(self, term: str) -> str:
        if term not in self._norm_cache:
            self._norm_cache[term] = normalize_term(term)
        return self._norm_cache[term]

    def _resolve_sector(self, raw_sector: str) -> tuple[str, list[str]]:
        """Resolve sector name (possibly PT-BR/ES) to (display_name, keywords)."""
        n = self._norm(raw_sector)
        # Direct English sector
        if n in SECTOR_ALIASES and isinstance(SECTOR_ALIASES[n], list):
            return n, SECTOR_ALIASES[n]
        # PT-BR/ES alias pointing to English key
        if n in SECTOR_ALIASES and isinstance(SECTOR_ALIASES[n], str):
            en_key = SECTOR_ALIASES[n]
            keywords = SECTOR_ALIASES.get(en_key, [en_key])
            if isinstance(keywords, str):
                keywords = [keywords]
            return f"{raw_sector} ({en_key})", keywords
        # Check MULTILINGUAL_ALIASES for sector-like terms
        if n in MULTILINGUAL_ALIASES:
            return raw_sector, MULTILINGUAL_ALIASES[n]
        return raw_sector, [n]

    def _resolve_type(self, raw_type: str) -> str | None:
        """Resolve type filter to module path prefix."""
        n = self._norm(raw_type)
        return TYPE_ALIASES.get(n, TYPE_ALIASES.get(raw_type.lower()))

    def _expand_keywords(self, normalized_term: str) -> set[str]:
        """Expand a single normalized term to all related keywords."""
        keywords: set[str] = {normalized_term}
        # Check multilingual aliases
        if normalized_term in MULTILINGUAL_ALIASES:
            keywords.update(MULTILINGUAL_ALIASES[normalized_term])
        # Also check partial matches in alias keys
        for alias_key, alias_vals in MULTILINGUAL_ALIASES.items():
            if normalized_term in alias_key or alias_key in normalized_term:
                keywords.update(alias_vals)
                keywords.add(alias_key)
        return keywords

    def search(self, raw_term: str) -> "SearchResult":
        """Main search entry point. Returns a SearchResult."""
        raw_term = raw_term.strip()
        if not raw_term:
            return SearchResult(query=raw_term, modules=[], error="Empty search term.")

        lower = raw_term.lower()
        norm = self._norm(raw_term)

        # ── sector=X filter ──────────────────────────────────────────────────
        sector_match = re.match(r"^sector=(.+)$", lower)
        if sector_match:
            sector_raw = sector_match.group(1).strip()
            display, keywords = self._resolve_sector(sector_raw)
            found: set[str] = set()
            for kw in keywords:
                for m in self.modules:
                    if kw.lower() in m.lower():
                        found.add(m)
            if not found:
                known = sorted(k for k, v in SECTOR_ALIASES.items() if isinstance(v, list))
                return SearchResult(
                    query=raw_term,
                    modules=[],
                    error=f"No modules for sector '{sector_raw}'.",
                    suggestions=self._suggest_sectors(sector_raw, known[:10]),
                    hint="Known sectors (EN): " + ", ".join(known[:15]),
                )
            return SearchResult(query=raw_term, modules=sorted(found),
                                display_name=f"sector '{display}'")

        # ── type=X filter ─────────────────────────────────────────────────────
        type_match = re.match(r"^type=(.+)$", lower)
        if type_match:
            type_raw = type_match.group(1).strip()
            prefix = self._resolve_type(type_raw)
            if prefix is None:
                known_types = sorted(set(v.rstrip("/") for v in TYPE_ALIASES.values()))
                return SearchResult(
                    query=raw_term,
                    modules=[],
                    error=f"Unknown type '{type_raw}'.",
                    hint="Known types: " + ", ".join(known_types),
                )
            found = [m for m in self.modules if prefix.rstrip("/") in m.lower()]
            return SearchResult(query=raw_term, modules=sorted(found),
                                display_name=f"type '{type_raw}'")

        # ── Direct keyword search (English module path) ───────────────────────
        direct_matches = [m for m in self.modules if norm in m.lower() or lower in m.lower()]

        # ── Multilingual expansion ─────────────────────────────────────────────
        expanded_keywords = self._expand_keywords(norm)
        expanded_matches: set[str] = set(direct_matches)
        for kw in expanded_keywords:
            for m in self.modules:
                if kw.lower() in m.lower():
                    expanded_matches.add(m)

        all_matches = sorted(expanded_matches)

        if all_matches:
            # If we got more from expansion, note it
            expansion_note = None
            if expanded_matches - set(direct_matches):
                expansion_note = "Also matched via multilingual aliases."
            return SearchResult(query=raw_term, modules=all_matches,
                                expansion_note=expansion_note)

        # ── No matches: suggest alternatives ─────────────────────────────────
        suggestions = self._suggest_terms(norm, raw_term)
        known_langs = self._find_in_aliases(norm)
        return SearchResult(
            query=raw_term,
            modules=[],
            error=f"No modules found for '{raw_term}'.",
            suggestions=suggestions,
            multilingual_hint=known_langs,
        )

    def _suggest_terms(self, norm: str, raw: str) -> list[str]:
        """Generate 'did you mean?' suggestions via edit distance."""
        candidates: list[tuple[int, str]] = []
        # Check alias keys
        for key in list(MULTILINGUAL_ALIASES.keys()) + list(SECTOR_ALIASES.keys()):
            if isinstance(SECTOR_ALIASES.get(key), str):
                continue  # skip PT-BR->EN redirects in sector aliases
            dist = _edit_distance(norm, self._norm(key))
            if dist <= 2:
                candidates.append((dist, key))
        # Check module path fragments
        all_parts: set[str] = set()
        for m in self.modules:
            parts = m.replace("industrialxpl.modules.", "").split(".")
            all_parts.update(parts)
        for part in all_parts:
            dist = _edit_distance(norm, part)
            if dist <= 1 and len(part) > 3:
                candidates.append((dist, part))
        candidates.sort()
        return [c[1] for c in candidates[:5]]

    def _suggest_sectors(self, raw: str, known: list[str]) -> list[str]:
        """Suggest similar sector names."""
        norm = self._norm(raw)
        candidates = [(d, k) for k in known
                      if (d := _edit_distance(norm, k)) <= 3]
        candidates.sort()
        return [c[1] for c in candidates[:5]]

    def _find_in_aliases(self, norm: str) -> str | None:
        """Return hint if the term appears in any alias value."""
        matches = [k for k, vals in MULTILINGUAL_ALIASES.items()
                   if isinstance(vals, list) and any(norm in v for v in vals)]
        if matches:
            return "Related terms: " + ", ".join(matches[:5])
        return None


class SearchResult:
    """Result of a search query."""

    def __init__(
        self,
        query: str,
        modules: list[str],
        display_name: str = "",
        error: str = "",
        suggestions: list[str] | None = None,
        hint: str = "",
        multilingual_hint: str | None = None,
        expansion_note: str | None = None,
    ) -> None:
        self.query = query
        self.modules = modules
        self.display_name = display_name or query
        self.error = error
        self.suggestions = suggestions or []
        self.hint = hint
        self.multilingual_hint = multilingual_hint
        self.expansion_note = expansion_note

    @property
    def found(self) -> bool:
        return bool(self.modules)

    def __len__(self) -> int:
        return len(self.modules)


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein edit distance (capped at min(len(a),len(b))+2 for speed)."""
    if not a:
        return len(b)
    if not b:
        return len(a)
    if abs(len(a) - len(b)) > 4:
        return 99
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev[j - 1] + cost)
    return dp[n]
