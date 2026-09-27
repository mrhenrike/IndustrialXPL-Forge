"""Multilingual search engine for IXF module discovery.

Supports search in:
  - English (default, module paths are in English)
  - Portuguese BR (pt-BR): with and without accents
  - Spanish (es): common industrial/OT terms

Features:
  - Unicode normalization: accepts accented chars (minério = minerio = mining)
  - Multilingual alias dictionary: maps translated terms to English keywords
  - Sector aliases: maps industries to relevant module keywords
  - Fuzzy suggestions: "Did you mean X?" when no match is found
  - Type filters: search type=scanner, type=exploit, etc.
  - Sector filters: search sector=mineracao, sector=energia, etc.
"""

from __future__ import annotations

import unicodedata
import re
from typing import List, Dict, Optional, Tuple, Set


def normalize_term(term: str) -> str:
    """Normalize a search term for multilingual matching.

    Steps:
      1. Lowercase
      2. NFD decomposition (separate base chars from diacritics)
      3. Strip combining diacritical marks (accents, cedilla, etc.)
      4. Replace hyphens, underscores and spaces with empty (for compound words)
      5. ASCII-only result

    Examples:
      "mineracao"  -> "mineracao"
      "mineracao"  -> "mineracao"  (already normalized)
      "mineração"  -> "mineracao"
      "minério"    -> "minerio"
      "Água"       -> "agua"
      "çu"         -> "cu"
      "oil & gas"  -> "oil  gas"
    """
    if not term:
        return ""
    nfkd = unicodedata.normalize("NFD", term.lower())
    # Remove combining characters (accents, cedilla becomes c, tilde becomes n, etc.)
    stripped = "".join(c for c in nfkd if unicodedata.category(c) != "Mn")
    return stripped.strip()


# ─── Multilingual alias dictionary ────────────────────────────────────────────
# Format: {normalized_term: [english_keywords_for_module_search]}
# Term can be in PT-BR, ES, synonyms, abbreviations, or common misspellings.
# English terms are included so they work without normalization too.

MULTILINGUAL_ALIASES: Dict[str, List[str]] = {
    # ── Mining / Mineração / Minería ─────────────────────────────────────────
    "minerio":       ["mining", "fms", "minestar", "wenco", "caterpillar", "lorawan", "gnss"],
    "mineracao":     ["mining", "fms", "minestar", "wenco", "caterpillar", "lorawan", "gnss"],
    "mineradora":    ["mining", "fms", "minestar", "wenco", "caterpillar", "lorawan", "gnss"],
    "mineradoras":   ["mining", "fms", "minestar", "wenco", "caterpillar", "lorawan", "gnss"],
    "mina":          ["mining", "fms", "minestar"],
    "minas":         ["mining", "fms", "minestar"],
    "garimpo":       ["mining"],
    "mineria":       ["mining", "fms", "minestar"],  # ES: minería
    "extrativismo":  ["mining"],
    "lavra":         ["mining"],
    "fms":           ["fms", "mining", "minestar", "wenco"],
    "frota":         ["fms", "minestar", "caterpillar"],
    "caminhao":      ["mining", "caterpillar", "komatsu"],
    "caminhoes":     ["mining", "caterpillar", "komatsu"],
    "haul":          ["mining", "caterpillar", "komatsu", "ahs"],
    "ahs":           ["gnss", "ahs", "mining", "caterpillar"],
    "autonomo":      ["ahs", "gnss", "mining"],
    "autonomos":     ["ahs", "gnss", "mining"],

    # ── Oil & Gas / Petroleo ──────────────────────────────────────────────────
    "petroleo":      ["oilgas", "oil_gas", "dnp3", "modbus", "night_dragon"],
    "gas":           ["gas", "oilgas", "dnp3", "modbus"],
    "refinaria":     ["oilgas", "modbus", "dnp3"],
    "refinamento":   ["oilgas", "modbus"],
    "hidrocarboneto":["oilgas"],
    "petrolifera":   ["oilgas", "night_dragon"],
    "duto":          ["oilgas", "scada", "dnp3"],
    "dutovia":       ["oilgas", "scada"],
    "oleo":          ["oilgas", "oil_gas"],
    "combustivel":   ["oilgas", "dnp3"],
    "petroquimica":  ["oilgas", "triton", "modbus"],
    "petrolero":     ["oilgas"],  # ES
    "gasoducto":     ["oilgas", "scada"],  # ES

    # ── Energy / Energia ─────────────────────────────────────────────────────
    "energia":       ["energy", "power", "dnp3", "iec104", "iec61850"],
    "eletrica":      ["energy", "power", "dnp3"],
    "eletrico":      ["energy", "power"],
    "eletricidade":  ["energy", "power"],
    "subestacao":    ["energy", "power", "dnp3", "iec104"],
    "usina":         ["energy", "power", "scada"],
    "termoeletrica": ["energy", "power"],
    "hidroeletrica": ["energy", "power", "scada"],
    "eolica":        ["energy", "power"],
    "solar":         ["energy", "power", "wattrouter"],
    "fotovoltaico":  ["energy", "wattrouter"],
    "transmissao":   ["energy", "dnp3", "iec104"],
    "distribuicao":  ["energy", "dnp3", "iec104"],
    "energia eletrica": ["energy", "power", "dnp3"],
    "energetico":    ["energy"],
    "energia":       ["energy", "power"],  # ES same
    "subestacion":   ["energy", "dnp3"],   # ES

    # ── Water / Agua ─────────────────────────────────────────────────────────
    "agua":          ["water", "modbus", "dnp3", "scada"],
    "aguas":         ["water", "modbus", "dnp3"],
    "saneamento":    ["water", "modbus", "dnp3"],
    "tratamento":    ["water", "modbus"],
    "esgoto":        ["water", "scada"],
    "abastecimento": ["water", "scada"],
    "reservatorio":  ["water", "scada"],
    "abastecimento de agua": ["water", "scada"],
    "agua potavel":  ["water", "modbus"],
    "agua":          ["water"],  # ES same

    # ── Manufacturing / Industria ─────────────────────────────────────────────
    "industria":     ["manufacturing", "plc", "modbus", "profinet", "enip"],
    "industrial":    ["manufacturing", "plc", "modbus", "profinet"],
    "fabrica":       ["manufacturing", "plc", "modbus"],
    "fabril":        ["manufacturing", "plc"],
    "producao":      ["manufacturing", "plc", "scada"],
    "automacao":     ["plc", "modbus", "profinet", "enip", "s7comm"],
    "automatizacao": ["plc", "modbus", "profinet"],
    "chao de fabrica":["manufacturing", "plc", "modbus"],
    "linha de producao": ["manufacturing", "plc"],
    "manufactura":   ["manufacturing", "plc"],  # ES
    "fabricacion":   ["manufacturing", "plc"],  # ES

    # ── Building / Predios ────────────────────────────────────────────────────
    "predio":        ["building", "bacnet", "bms", "hvac"],
    "edificio":      ["building", "bacnet", "bms"],
    "construcao":    ["building", "bacnet"],
    "predial":       ["building", "bacnet", "bms"],
    "climatizacao":  ["building", "hvac", "bacnet"],
    "ar condicionado": ["building", "hvac", "bacnet"],
    "hvac":          ["hvac", "bacnet", "building"],
    "bms":           ["bms", "bacnet", "building"],
    "elevador":      ["building", "bacnet"],
    "automaçao predial": ["building", "bacnet", "bms"],

    # ── Chemical / Quimica ────────────────────────────────────────────────────
    "quimica":       ["chemical", "modbus", "profinet", "triton", "safety"],
    "quimico":       ["chemical", "modbus", "profinet"],
    "petroquimica":  ["chemical", "oilgas", "triton"],
    "reator":        ["chemical", "safety", "triton"],
    "planta quimica": ["chemical", "modbus"],
    "quimico industrial": ["chemical"],
    "quimica":       ["chemical"],  # ES same

    # ── Maritime / Maritimo ────────────────────────────────────────────────────
    "maritimo":      ["maritime", "ais", "nmea", "vsat"],
    "maritima":      ["maritime", "ais", "nmea"],
    "navio":         ["maritime", "ais", "nmea"],
    "porto":         ["maritime", "ais"],
    "navegacao":     ["maritime", "ais", "nmea"],
    "embarcacao":    ["maritime", "ais"],
    "barco":         ["maritime", "ais"],
    "mar":           ["maritime", "ais"],
    "maritimo":      ["maritime"],  # ES same

    # ── Transport / Transporte ────────────────────────────────────────────────
    "ferroviario":   ["railway", "modbus", "profinet"],
    "ferrovia":      ["railway", "modbus"],
    "trem":          ["railway"],
    "metro":         ["railway"],
    "transporte":    ["railway", "automotive", "modbus"],
    "automovel":     ["automotive", "can"],
    "automovel":     ["automotive"],
    "veiculo":       ["automotive", "can"],
    "ferrocarril":   ["railway"],  # ES

    # ── Healthcare / Saude ────────────────────────────────────────────────────
    "hospital":      ["hospital", "modbus", "bacnet"],
    "saude":         ["hospital", "modbus", "bacnet"],
    "medico":        ["hospital", "bacnet"],
    "clinica":       ["hospital", "bacnet"],
    "laboratorio":   ["hospital"],
    "farmaceutico":  ["pharma", "batch", "opc"],
    "farmacia":      ["pharma"],

    # ── SCADA / Control ──────────────────────────────────────────────────────
    "controle":      ["plc", "scada", "modbus", "s7comm"],
    "controles":     ["plc", "scada"],
    "supervisorio":  ["scada", "hmi", "historian"],
    "clp":           ["plc", "modbus", "s7comm", "enip"],  # CLP = PLC in PT-BR
    "controlador":   ["plc", "modbus"],
    "ihu":           ["hmi", "scada"],  # IHM = HMI in PT-BR
    "ihm":           ["hmi", "scada"],
    "rtu":           ["rtu", "modbus", "dnp3"],
    "telemetria":    ["rtu", "dnp3", "modbus"],
    "sistema de controle": ["plc", "scada", "modbus"],
    "sis":           ["safety", "triton", "triconex"],
    "sistema de seguranca": ["safety", "triton"],
    "seguranca industrial": ["safety", "triton", "iec62443"],
    "controlador logico": ["plc", "modbus"],
    "controlador programavel": ["plc", "s7comm", "enip"],

    # ── Protocols in PT-BR ────────────────────────────────────────────────────
    "protocolo":     ["modbus", "s7comm", "dnp3", "bacnet", "profinet", "enip"],
    "comunicacao":   ["modbus", "s7comm", "dnp3"],
    "barramento":    ["modbus", "profinet", "enip"],
    "fieldbus":      ["profinet", "enip", "modbus"],
    "rede industrial": ["modbus", "profinet", "enip", "s7comm"],
    "opc":           ["opc", "havex"],
    "protocolo modbus": ["modbus"],
    "sem fio":       ["wireless", "lorawan", "wifi"],
    "sensor":        ["lorawan", "modbus", "dnp3"],
    "sensores":      ["lorawan", "modbus"],

    # ── Cybersecurity terms in PT-BR ─────────────────────────────────────────
    "vulnerabilidade":  ["cve", "exploit"],
    "vulnerabilidades": ["cve", "exploit"],
    "brecha":        ["cve", "exploit"],
    "falha":         ["cve", "exploit"],
    "falha de seguranca": ["cve"],
    "ataque":        ["exploit", "cve", "apt"],
    "malware":       ["malware", "apt", "triton", "stuxnet", "industroyer"],
    "ransomware":    ["malware", "wannacry", "notpetya", "ekans", "clop"],
    "intrusao":      ["exploit", "cve"],
    "invasao":       ["exploit", "cve"],
    "exploracao":    ["exploit", "cve"],
    "cve":           ["cve"],
    "credenciais":   ["creds", "default_creds"],
    "senha padrao":  ["creds", "default_creds"],
    "senhas":        ["creds"],
    "enumeracao":    ["scan", "scanner"],
    "varredura":     ["scanner", "scan", "detect"],
    "descoberta":    ["scanner", "discover", "detect"],
    "identificacao": ["scanner", "banner", "fingerprint"],
    "fingerprint":   ["banner", "scanner"],
    "avaliacao":     ["assessment"],
    "auditoria":     ["assessment", "iec62443", "nist"],
    "pentest":       ["exploit", "assessment", "cve"],
    "teste de invasao": ["exploit", "assessment"],
    "seguranca":     ["assessment", "cve", "exploit"],
    "ciberseguranca": ["assessment", "cve"],
    "cyber":         ["assessment", "cve", "exploit"],

    # Spanish cybersecurity
    "vulnerabilidad": ["cve", "exploit"],
    "ataque":        ["exploit", "cve", "apt"],
    "brecha de seguridad": ["cve"],
    "ciberseguridad": ["assessment", "cve"],
    "escaneo":       ["scanner", "scan"],
    "seguridad":     ["assessment"],
    "auditoria":     ["assessment"],  # same in ES

    # ── Vendor names in PT-BR / ES ────────────────────────────────────────────
    "siemens":       ["siemens"],
    "schneider":     ["schneider", "schneider_electric", "modicon"],
    "schneider electric": ["schneider", "schneider_electric"],
    "modicon":       ["modicon", "schneider"],
    "rockwell":      ["rockwell", "allen_bradley", "logix"],
    "allen bradley": ["allen_bradley", "rockwell"],
    "abb":           ["abb"],
    "honeywell":     ["honeywell"],
    "emerson":       ["emerson"],
    "ge":            ["ge", "general_electric"],
    "general electric": ["ge"],
    "yokogawa":      ["yokogawa"],
    "mitsubishi":    ["mitsubishi"],
    "beckhoff":      ["beckhoff"],
    "phoenix contact": ["phoenix"],
    "wago":          ["wago"],
    "omron":         ["omron"],
    "caterpillar":   ["caterpillar", "minestar", "mining"],
    "komatsu":       ["komatsu", "mining"],
    "hitachi":       ["wenco", "mining"],
    "sap":           ["sap", "netweaver"],
    "vale":          ["mining", "sap", "lorawan"],
    "petrobras":     ["oilgas", "scada", "modbus"],
    "cemig":         ["energy", "power", "dnp3"],

    # ── Assessment frameworks ─────────────────────────────────────────────────
    "iec62443":      ["iec62443", "zone_conduit"],
    "norma":         ["assessment", "iec62443", "nist"],
    "conformidade":  ["assessment", "iec62443", "nist"],
    "nist":          ["nist", "assessment"],
    "mitre":         ["mitre_ics", "assessment"],
    "mitre ics":     ["mitre_ics"],
    "ics":           ["ics", "modbus", "s7comm", "dnp3"],
    "ot":            ["ot", "modbus", "scada", "plc"],
    "tecnologia operacional": ["ot", "scada", "plc", "modbus"],
    "scada":         ["scada", "hmi", "historian", "opc"],
    "iiot":          ["iiot", "mqtt", "lorawan"],
    "internet das coisas": ["iot", "mqtt", "coap", "lorawan"],
    "iot":           ["iot", "mqtt", "coap"],

    # ── APT / Malware names ───────────────────────────────────────────────────
    "stuxnet":       ["stuxnet", "siemens"],
    "triton":        ["triton", "trisis", "triconex", "safety"],
    "trisis":        ["triton", "trisis"],
    "industroyer":   ["industroyer", "crashoverride"],
    "crashoverride": ["crashoverride", "industroyer"],
    "blackenergy":   ["blackenergy"],
    "havex":         ["havex", "dragonfly", "opc"],
    "sandworm":      ["industroyer", "crashoverride", "notpetya"],
    "apt":           ["apt", "malware"],
    "ameaca persistente avancada": ["apt", "malware"],

    # ── Common typos / alternate spellings ───────────────────────────────────
    "mineriacao":    ["mining"],   # common typo
    "petrolio":      ["oilgas"],   # common misspelling
    "eletricio":     ["energy"],   # typo
    "automacao":     ["plc", "modbus", "profinet"],
    "automatizacao": ["plc", "modbus"],
}

# ─── Sector aliases (for search sector=X) ────────────────────────────────────
SECTOR_ALIASES: Dict[str, List[str]] = {
    # English
    "mining":        ["mining", "fms", "minestar", "wenco", "caterpillar", "lorawan", "gnss", "ahs", "komatsu", "pitram"],
    "oilgas":        ["oilgas", "oil_gas", "night_dragon", "vsat", "cobham", "dnp3", "modbus"],
    "oil":           ["night_dragon", "oil_gas", "dnp3", "modbus"],
    "gas":           ["gas", "modbus", "dnp3"],
    "energy":        ["siemens", "abb", "schneider", "ge", "emerson", "power", "scada", "dnp3"],
    "water":         ["water", "modbus", "dnp3", "scada"],
    "pharma":        ["pharma", "batch", "opc", "profinet"],
    "manufacturing": ["modbus", "enip", "profinet", "plc", "rockwell", "siemens", "abb"],
    "building":      ["bacnet", "knx", "bms", "hvac", "automated_logic", "webctrl"],
    "automotive":    ["profinet", "can", "upa", "obd"],
    "maritime":      ["ais", "nmea", "vsat", "gps"],
    "aviation":      ["ads_b", "asterix", "fms"],
    "railway":       ["modbus", "profinet", "dnp3", "cbtc"],
    "chemical":      ["modbus", "profinet", "siemens", "safety", "triton"],
    "nuclear":       ["modbus", "profinet", "siemens", "plc"],
    "hospital":      ["modbus", "bacnet", "bms", "ics"],
    "datacenter":    ["modbus", "bacnet", "bms", "hvac", "ups"],
    "smart_grid":    ["dnp3", "iec104", "iec61850", "modbus"],
    "scada":         ["scada", "hmi", "historian", "opc"],
    "plc":           ["plc", "modbus", "s7comm", "enip", "profinet"],
    "dcs":           ["dcs", "yokogawa", "emerson", "abb", "honeywell"],
    "rtu":           ["rtu", "modbus", "dnp3"],
    "sap":           ["sap", "netweaver", "cve_2025_31324"],

    # PT-BR aliases -> map to English sector keys
    "minerio":       "mining",
    "mineracao":     "mining",
    "mineradora":    "mining",
    "mina":          "mining",
    "garimpo":       "mining",
    "petroleo":      "oilgas",
    "oleo":          "oilgas",
    "combustivel":   "oilgas",
    "refinaria":     "oilgas",
    "energia":       "energy",
    "eletrica":      "energy",
    "agua":          "water",
    "saneamento":    "water",
    "farmaceutico":  "pharma",
    "industria":     "manufacturing",
    "fabrica":       "manufacturing",
    "predio":        "building",
    "edificio":      "building",
    "predial":       "building",
    "maritimo":      "maritime",
    "navio":         "maritime",
    "ferroviario":   "railway",
    "ferrovia":      "railway",
    "quimica":       "chemical",
    "hospital":      "hospital",
    "saude":         "hospital",

    # ES aliases -> map to English sector keys
    "mineria":       "mining",
    "petroleo":      "oilgas",
    "maritimo":      "maritime",
    "ferrocarril":   "railway",
    "manufactura":   "manufacturing",
    "quimico":       "chemical",
    "hospital":      "hospital",
    "energia":       "energy",
}

# ─── Module type aliases ──────────────────────────────────────────────────────
TYPE_ALIASES: Dict[str, str] = {
    "scanner":        "scanners/",
    "scanners":       "scanners/",
    "varredura":      "scanners/",
    "escaneo":        "scanners/",
    "exploit":        "exploits/",
    "exploits":       "exploits/",
    "exploracao":     "exploits/",
    "explotacion":    "exploits/",
    "cve":            "cve/",
    "vulnerabilidade": "cve/",
    "assessment":     "assessment/",
    "avaliacao":      "assessment/",
    "auditoria":      "assessment/",
    "evaluacion":     "assessment/",
    "creds":          "creds/",
    "credenciais":    "creds/",
    "credentials":    "creds/",
    "credenciales":   "creds/",
    "malware":        "cve/malware",
    "apt":            "cve/apt",
}


class SearchEngine:
    """Multilingual module search engine."""

    def __init__(self, modules: List[str]) -> None:
        self.modules = modules
        self._norm_cache: Dict[str, str] = {}

    def _norm(self, term: str) -> str:
        if term not in self._norm_cache:
            self._norm_cache[term] = normalize_term(term)
        return self._norm_cache[term]

    def _resolve_sector(self, raw_sector: str) -> Tuple[str, List[str]]:
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
            return "{} ({})".format(raw_sector, en_key), keywords
        # Check MULTILINGUAL_ALIASES for sector-like terms
        if n in MULTILINGUAL_ALIASES:
            return raw_sector, MULTILINGUAL_ALIASES[n]
        return raw_sector, [n]

    def _resolve_type(self, raw_type: str) -> Optional[str]:
        """Resolve type filter to module path prefix."""
        n = self._norm(raw_type)
        return TYPE_ALIASES.get(n, TYPE_ALIASES.get(raw_type.lower()))

    def _expand_keywords(self, normalized_term: str) -> Set[str]:
        """Expand a single normalized term to all related keywords."""
        keywords: Set[str] = {normalized_term}
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
            found: Set[str] = set()
            for kw in keywords:
                for m in self.modules:
                    if kw.lower() in m.lower():
                        found.add(m)
            if not found:
                known = sorted(k for k, v in SECTOR_ALIASES.items() if isinstance(v, list))
                return SearchResult(
                    query=raw_term,
                    modules=[],
                    error="No modules for sector '{}'.".format(sector_raw),
                    suggestions=self._suggest_sectors(sector_raw, known[:10]),
                    hint="Known sectors (EN): " + ", ".join(known[:15]),
                )
            return SearchResult(query=raw_term, modules=sorted(found),
                                display_name="sector '{}'".format(display))

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
                    error="Unknown type '{}'.".format(type_raw),
                    hint="Known types: " + ", ".join(known_types),
                )
            found = [m for m in self.modules if prefix.rstrip("/") in m.lower()]
            return SearchResult(query=raw_term, modules=sorted(found),
                                display_name="type '{}'".format(type_raw))

        # ── Direct keyword search (English module path) ───────────────────────
        direct_matches = [m for m in self.modules if norm in m.lower() or lower in m.lower()]

        # ── Multilingual expansion ─────────────────────────────────────────────
        expanded_keywords = self._expand_keywords(norm)
        expanded_matches: Set[str] = set(direct_matches)
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
            error="No modules found for '{}'.".format(raw_term),
            suggestions=suggestions,
            multilingual_hint=known_langs,
        )

    def _suggest_terms(self, norm: str, raw: str) -> List[str]:
        """Generate 'did you mean?' suggestions via edit distance."""
        candidates: List[Tuple[int, str]] = []
        # Check alias keys
        for key in list(MULTILINGUAL_ALIASES.keys()) + list(SECTOR_ALIASES.keys()):
            if isinstance(SECTOR_ALIASES.get(key), str):
                continue  # skip PT-BR->EN redirects in sector aliases
            dist = _edit_distance(norm, self._norm(key))
            if dist <= 2:
                candidates.append((dist, key))
        # Check module path fragments
        all_parts: Set[str] = set()
        for m in self.modules:
            parts = m.replace("industrialxpl.modules.", "").split(".")
            all_parts.update(parts)
        for part in all_parts:
            dist = _edit_distance(norm, part)
            if dist <= 1 and len(part) > 3:
                candidates.append((dist, part))
        candidates.sort()
        return [c[1] for c in candidates[:5]]

    def _suggest_sectors(self, raw: str, known: List[str]) -> List[str]:
        """Suggest similar sector names."""
        norm = self._norm(raw)
        candidates = [(d, k) for k in known
                      if (d := _edit_distance(norm, k)) <= 3]
        candidates.sort()
        return [c[1] for c in candidates[:5]]

    def _find_in_aliases(self, norm: str) -> Optional[str]:
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
        modules: List[str],
        display_name: str = "",
        error: str = "",
        suggestions: Optional[List[str]] = None,
        hint: str = "",
        multilingual_hint: Optional[str] = None,
        expansion_note: Optional[str] = None,
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
