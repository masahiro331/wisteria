# Meeting Minutes - 2026-04-25

## Discussion Topics
- Project goal and requirements definition
- Technology stack selection
- Phase planning and MVP definition
- CLI command design

## Decisions Made

### Project Goal
Build a free, fast vulnerability database that does not depend on commercial vulnerability DBs.

### Technology Stack
- Language: Go
- Database: PostgreSQL
- Form: CLI tool (DB construction tool)
- Data sources: OSV + MITRE CVEListV5 (https://github.com/CVEProject/cvelistV5)
- AI: Claude API + local LLM (OSS)

### CLI Command Design
```
wisteria fetch osv
wisteria fetch cve
wisteria fetch all
```

### Local Storage
- Cache directory: `~/.cache/wisteria/`

### Phase Plan

#### Phase 1 - MVP: Data Collection & Local Storage
- Download OSV data and save to local files
- Download MITRE CVEListV5 and save to local files
- Periodic batch execution mechanism

#### Phase 2 - AI Processing
- Summary generation via Claude API / local LLM
- Vulnerability labeling, exploit code analysis, etc.

#### Phase 3 - DB Storage
- Store data in PostgreSQL
- Product identifier design and numbering

### Deferred Decisions
- Product identifier design: Review after examining actual data

## Vulnerability DB Requirements
0. Unique identifier assignment for affected products (resolve naming variations deterministically using Markov chains, etc.; use AI as needed)
1. Product overview summary (AI-generated from multiple sources)
2. Vulnerability identifier (deterministic)
3. Vulnerability summary (AI-generated from multiple sources)
   a. Vulnerability types that can be combined for exploitation
4. Vulnerability references (deterministic)
5. Exploit code existence (deterministic)
   a. If exploit exists: is it exploitable? (AI)
   b. If no exploit: can one be developed? (AI)
6. EPSS score / CVSS score / attack vector (deterministic)
7. Vulnerability labeling (XSS, prototype pollution, etc.) (AI)
8. Are attacks observed in the wild? (social temperature)

## Next Steps
1. Initialize Go project (`go mod init`)
2. Set up CLI framework (cobra)
3. Implement `wisteria fetch osv` command (Phase 1)
4. Implement `wisteria fetch cve` command (Phase 1)
