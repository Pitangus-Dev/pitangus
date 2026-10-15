English · [Español](es/modelado-de-amenazas.md)

# Threat modeling

Scanners find flaws in what's already written. **Threat modeling** looks at the design: you draw the system (its
components, the data flowing between them and the trust boundaries they cross) and ask what could go wrong at each
point. **Threats** (`#/threats`) lets you draw that model, apply a method such as STRIDE, and check each threat
against what your scans found. A threat is a scenario to review, not a confirmed flaw. Terms are explained in the
[glossary](glossary.md).

## Prerequisites

- Pitangus running. A model needs no repositories, but linking its components to scanned repositories or verified
  domains is what brings in evidence ([Scan your code](scanning-code.md)).
- To get component suggestions from a GitHub repository: the GitHub App installed on it, with `contents: read`
  ([Connecting GitHub](github-app.md)).

## Create a model

1. Open **Threats** and click **New model**.
2. Give the project a name (for example "Payments" or "Customer portal") and choose an **Approach** (below). You can
   change it later without losing the diagram.
3. Optionally, under **Start from repositories (optional)**, pick one or more repositories and click
   **Create and propose components**: Pitangus suggests components and flows from their manifests (see
   [Suggestions from repositories](#suggestions-from-repositories)).
4. Draw or adjust the system in **Diagram**, then click **Save and recalculate**.

Each model is a project: associate the **Project repositories** whenever you want, one or several (microservices,
microfrontends). A component linked to a repository adds it to the list automatically.

### Approaches

| Approach | What for | What Pitangus does |
| --- | --- | --- |
| STRIDE | Security threats to components and flows (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege) | Built-in rules on the diagram (`TM-*`) |
| LINDDUN | Threats to people's privacy | Built-in rules on the elements that hold personal data (`PV-*`) |
| PASTA | Business risk in seven stages | Stages with notes; stages 3, 4 and 5 are fed by the diagram, STRIDE and the scans |
| Attack trees | Paths toward an attacker's goal | AND/OR tree editor with difficulty, element and mitigation; works out which paths are still open |
| MITRE ATT&CK | Real attackers' techniques | A selection of techniques (web, API, containers, cloud) to map onto components, with suggestions and a link to attack.mitre.org; any other technique ID can be added too |
| Custom | Your team's method | The diagram plus whichever tools you turn on: STRIDE or LINDDUN rules, your own threats, PASTA stages, attack trees, ATT&CK and the element table |

In any approach you can **add your own threats**: title, scenario, category, element, severity, likelihood, impact,
owner and mitigation. Each approach has a **Guide** (what each letter means, the stages, how to build a tree) that
opens next to your work and remembers whether you left it open; STRIDE and LINDDUN categories show their guiding
question on hover.

**The built-in rules are visible** (STRIDE `TM-S01`…`TM-E02` in `pitangus/modules/threats/model.py`, LINDDUN `PV-*`
in `pitangus/modules/threats/methods.py`). Each threat says what triggers it on that element, its severity, its
mitigations and its CWEs. The severity starts from the rule's base, goes one level up if the element is exposed to
the internet and carries credentials or payments, and one level down if it's internal and not very sensitive.

## Draw the system

In **Diagram**:

- **Components**: add them from the canvas toolbar and drag them. Types: actor, web app, API, service, function,
  database, cache, queue, storage, third party and identity provider. **Other type (you name it)** creates a custom
  type with any name and a **base role**, which decides which automatic rules apply to it.
- **Flows**: connect two components by dragging between their connection points. A flow says what it carries, its
  protocol, its data, and whether it's authenticated and encrypted in transit.
- **Trust boundaries** are boxes you can move (their components move with them) and resize. A component belongs to
  the boundary that contains its center.
- **Select an element** to edit it in the side panel: name, type, technology, description, the data it stores or
  handles, and properties such as internet-facing or authenticates. There you also link a component to a repository
  or a domain, and set its **Folder in the repository** (see [Evidence](#evidence-not-confirmation)).
- **Resize** components and boundaries by dragging an edge or a corner (the handles appear on hover); hold **Shift**
  to keep the aspect ratio.
- **Tidy up** arranges everything in layers (actors, then applications, then APIs and services, then data and third
  parties), each boundary as a block that contains its components.
- Flow labels are placed where they don't overlap components or other labels; long labels are shortened and shown in
  full when you select or hover the flow.

Positions are saved with the model and used by the exports. **Table** is there for editing many components, flows and
boundaries at once. If the server is updated while you work, open tabs show **Reload**: save first.

## Suggestions from repositories

From each repository in the project (when you create it or later), Pitangus suggests components and flows and
**adds them to the diagram without duplicating** what's there, respecting what your team drew: new items go into
their boundary or to the right.

- Up to 10 repositories at a time. Repositories from the GitHub App are read on the spot, scanned or not; a
  repository from the server's workspace is proposed from its latest scan.
- Only manifests are read, through GitHub's API (repository tree and files; the repository isn't downloaded): `package.json`, `requirements*.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `Dockerfile` and
  compose files, up to 40 files, leaving out `node_modules`, fixtures and tests.
- FastAPI, Next.js, Express or axum become processes; psycopg, Prisma, Mongoose or sqlx become databases (an ORM is
  merged with its engine); Stripe, Twilio, S3, next-auth or an LLM SDK become third parties or identity providers.
- **Each suggested component cites the dependency and the file it came from** and is marked as proposed from the
  repository, so the team can correct it.
- Only names are kept, never versions or configuration values.

An unscanned repository is modeled the same way, but its threats have no evidence until it's scanned.

## Evidence, not confirmation

When a component is linked to a repository and that code has open findings with one of a threat's CWEs, the threat
is marked **Evidenced** and links to those findings (**Evidence from scans**). It's a signal to review, not proof that
the scenario is exploitable.

- In a monorepo, set the component's **Folder in the repository** (for example `frontend/`) so only findings from
  its own code count. Without a folder, the whole repository counts, and the threat says so.
- Findings in excluded paths, and findings dismissed in triage, don't count.
- Dependency advisories are evidence of "vulnerable dependencies", not of injection in your own code.

## Decisions

Each threat can be closed with a decision: **Mitigated** (say which control mitigates it and where it can be
verified), **Accepted** (why, and until when) or **Not applicable** (why it doesn't apply to this system). Each
decision keeps its reason, author and date, and can be reopened. If open findings point to the threat, the dialog
says so before you decide.

## Import and export a model as JSON

The model has a portable JSON format you can version, edit by hand or ask an AI assistant to write.

**Import.** In the list, **Import JSON** opens a wizard with a complete example for each approach, an editor to
paste or change the JSON, **Format JSON** (two-space indentation; on a syntax error it says the line and column), file
upload (600 KB at most), download and copy of the example, and **Copy AI prompt**: the full contract (allowed values,
id and reference rules, the ATT&CK ID format and a minimal valid example) for an AI assistant. **Validate JSON** checks
it without creating anything and lists **every problem at once**, in three levels: **errors** (they block the
import), **warnings** (something that matters was changed or couldn't be used) and **minor adjustments** (a synonym
read as our field, a field kept as a custom property). Identical problems are grouped ("description read as scenario
· in 12 team threats") and open to each place; click one to jump to it in the editor. The status line counts errors
and warnings only ("Ready to import with 2 warnings"); the minor adjustments are folded under their count.

**Saved means shown; nothing you write is thrown away.** Only structural integrity stops the import: invalid JSON, a
wrong `format` or `version`, missing or repeated ids, references (`source`, `target`, `element`, `parent`, a
boundary's `components`) to ids that don't exist, wrong types (text, `true`/`false`, lists), an ATT&CK ID that isn't
one, sizes over their limit, and sections a fixed approach doesn't use. Everything else is kept and shown:

- **Descriptions** on components, flows and boundaries are stored, shown in the inspector (and as a tooltip on the
  diagram) and printed in the reports' flow and trust boundary appendices.
- **Assumptions** (`assumptions: [{"id": "a1", "text": "…"}]`, or a plain list of sentences) are a section of the
  model: the **Context** tab edits them and they open the report, before the analysis.
- **Fields Pitangus doesn't know** become **custom properties** of their object: listed and editable (add, rename,
  remove) in the inspector, the threat dialog, the tree and the ATT&CK table; on the diagram as a tooltip; in the
  reports in a "Custom properties" appendix; and exported back to the JSON where they came from. Unknown fields of the
  model itself are its own properties and sections, shown in **Context** and in the report (a list of objects as a
  table, a list as bullets). A field close to one of ours ("sevirity") is still kept, with a warning asking whether
  you meant ours.
- **Synonyms** are read as our fields with a minor adjustment: `component_id`, `component`, `element_id` or `flow_id`
  → `element`; a threat's `description` → `scenario` (joined to it if both are present); a tree's `name` or `title`
  → `goal` (joined in front of it); a step's `label` → `text` and `type` → `gate`; a mapping's `technique_id` →
  `technique` and `notes` → `note`; a flow's `from`/`to` → `source`/`target`; and more. Field names ignore case and
  hyphens. The full list is in the JSON Schema (`x-pitangus-aliases`) and in the AI prompt. If both our field and a
  synonym come with different values, ours is used and the synonym stays as a custom property (warning).

**Your own values.** Our lists are suggestions; every team has its own. A value Pitangus doesn't know becomes a new
option of that field for the workspace (it is offered in the selector next time):

| Field | Pitangus knows | Any other value |
| --- | --- | --- |
| Flow `protocol` | `https`, `http`, `grpc`, `websocket`, `sql`, `amqp`, `redis`, `smtp`, `sftp`, `other` | Kept as written (24 characters at most, e.g. `wifi`, `mqtt`). Pitangus can't tell whether it's encrypted: set `encrypted` (then it's only a minor adjustment). |
| Component `kind` | `actor`, `web_app`, `api`, `service`, `function`, `database`, `cache`, `queue`, `storage`, `external`, `identity` | Kept as your own type (`kind: custom`, `custom_kind`), analyzed as `custom_base` (default `service`). |
| `data` classes | `public`, `internal`, `confidential`, `pii`, `credentials`, `payment` | Kept as written (40 characters at most); it counts as internal data and no privacy or credential rules apply to it. |
| `severity`, `likelihood`, `impact`, `difficulty` | `critical`, `high`, `medium`, `low` (and the synonyms `crit`, `med`, `moderate`, `severe`…) | Kept with its name as your own level. It sorts after the known levels unless you give it an equivalent (`level_equivalents: {"severity": {"Severe": "high"}}`, or **sorts like** in the threat dialog). |
| ATT&CK mapping `status` | `relevant`, `mitigated`, `not_applicable` (and `potential`, `possible`, `addressed`, `n/a`…) | Kept as your own status. |
| Team threat `category` | STRIDE's and LINDDUN's categories | Free text in every approach except STRIDE and LINDDUN (see below). |

**What stays the method's own.** A template keeps its principle: a **STRIDE** model has STRIDE's six categories and a
**LINDDUN** one LINDDUN's seven (a code, or the category's name in English or Spanish, is read as its code); **PASTA**
has its seven stages; an attack tree step is **AND** or **OR**. A value outside the method is kept as a custom
property with a warning that suggests the **Custom** approach to model with your own categories or sections. An
approach Pitangus doesn't have is imported as Custom, keeping its name as a property. **Custom** is full freedom: any
category, status, scale, section or field is accepted and shown; a section the file brings turns its module on.

**ATT&CK.** Pitangus includes the full MITRE ATT&CK Enterprise catalog (v19.2, every technique and sub-technique with
its name and tactics), offline. Any real ID is recognized and named (T1552.004 is "Private Keys"); our selection is
only what we suggest. A well-formed ID that isn't in ATT&CK is kept with the warning "not found in ATT&CK v19.2", and
a revoked one names its replacement when MITRE gives one. To refresh it, change the pinned release in
`scripts/attack-catalog.py` and run `make attack-catalog`.

**JSON Schema.** The format is described as a JSON Schema (draft 2020-12): download it from the import wizard
(**Download JSON Schema**) or read it in the repository at `web/src/examples/threat-models/schema.json`. It is
generated from the same lists the importer uses (`make openapi`), and so is the AI prompt. A document that
validates against it imports without errors. The `/api/threat-models/validate` route answers
`{…counts, "problems": [{"severity", "path", "id", "code", "message"}]}`, where `severity` is `error`, `warning` or
`info`, `path` is a JSON Pointer such as `/model/flows/3/protocol` and `code` is the same for identical problems; with
errors it answers 400 with `error` (the first one) and the same `problems` list.

**Export.** In the editor, **Export → Model JSON (re-importable)** downloads `model.json`: the full diagram (positions,
components, flows and boundaries, with their descriptions), the approach, the custom modules, the assumptions, the
threats your team wrote, PASTA stages, attack trees, ATT&CK techniques, your own levels' equivalents and every custom
property back in its place.

The importer takes both the envelope the panel downloads (`{"format": "pitangus-threat-model", "version": 1,
"model": {…}}`) and a bare model object. A minimal example:

```json
{
  "name": "Customer portal",
  "methodology": "custom",
  "custom_modules": ["stride", "trees", "manual"],
  "repository_refs": ["team/portal"],
  "components": [
    {"id": "customer", "name": "Customer", "kind": "actor"},
    {"id": "api", "name": "API", "kind": "api", "asset_ref": "team/portal", "data": ["pii"]}
  ],
  "flows": [{"id": "login", "source": "customer", "target": "api", "protocol": "https", "authenticated": false}],
  "boundaries": [{"id": "server", "name": "Server", "components": ["api"]}]
}
```

Rules worth knowing:

- **References are pending, never automatic links.** Repositories and domains in the file are kept as
  `repository_refs` and `asset_ref`. They don't need to exist when you import; link them later in the editor.
- **Layout is optional.** `position` (components), `size` (resized components) and `box` (boundaries) can be left
  out: the editor lays everything out. If the positions don't fit their boundaries (a box smaller than its
  components, or two boxes overlapping), the model is laid out again on import and the preview warns you.
- **Sections must match the approach.** The diagram is shared by every approach. STRIDE and LINDDUN accept your own
  threats; PASTA accepts its stages and trees; Attack trees accepts trees; ATT&CK accepts techniques. A file with a
  section its fixed approach doesn't use is rejected with a message saying which section doesn't belong and
  suggesting another approach or Custom (the section isn't dropped silently: you'd lose it). **Custom** accepts any
  combination: its modules (`stride`, `linddun`, `manual`, `pasta`, `trees`, `attack`, `elements`) are the ones in
  `custom_modules` plus those of the sections the file brings.
- When exporting a fixed approach, only its sections are included; data left over from another approach after
  switching doesn't leak into the file.
- Instance IDs, decisions and scan findings aren't part of the portable format.

## Other exports

From **Export** in the editor:

| Export | What it is |
| --- | --- |
| **PDF report** and **Markdown report** | For the development team: what to handle first, the diagram, the threats your team wrote, those with evidence in the scans, and the rule-based threats grouped by pattern, with the details in annexes. The model's threats aren't presented as confirmed flaws. |
| **SVG diagram** | The diagram on its own (`diagram.svg`); pending changes are saved before downloading. |
| **OWASP Threat Dragon** | Threat Dragon v2 JSON. Importing it into Threat Dragon hasn't been tested. |
| **pytm (Python)** | An OWASP pytm script (`tm.py`), for teams that keep their model as code. |

Downloads go through the authenticated API and show the actual error if they fail.

## Common errors

| What you see | Why | What to do |
| --- | --- | --- |
| "This isn't valid JSON: line 12, column 5" | A comma, quote or brace is wrong near there | Click the problem to jump to it, fix it, then **Format JSON** or validate again. |
| "… points to «x», which isn't the id of any element" | A reference to an id that doesn't exist | Fix the id, or add the component it refers to. |
| A warning that a value is your own | Pitangus doesn't know that protocol, type or data class | Nothing to fix: it's kept. Set what Pitangus can't infer (e.g. `encrypted`). |
| "STRIDE has only these categories…" | A category outside the method in a STRIDE or LINDDUN model | It's kept as a custom property. Use a category of the method, or the Custom approach. |
| "N minor adjustments" | Synonyms read as our fields, fields kept as custom properties | Nothing to fix; open them to see each one. |
| The import says a section doesn't belong | The section isn't allowed for that approach | Change `methodology`, or use `custom` and add the module to `custom_modules`. |
| "The file is over the 600 KB limit" | The model is too large | Split it into several models. |
| No components are proposed from a repository | Its manifests aren't among the supported ones, or the App can't read it | Check the App's access; add components by hand. |
| A threat shows no evidence | The component isn't linked to a scanned repository, or the folder excludes the findings | Link the repository, scan it, and check the component's folder. |

## Next steps

- [Scan your code and dependencies](scanning-code.md): the evidence behind each threat.
- [Findings, triage and remediation](findings.md).
- [Compliance evidence](compliance.md).
- [Glossary](glossary.md).
