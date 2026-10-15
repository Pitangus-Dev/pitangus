English · [Español](es/glosario.md)

# Glossary of application security terms

The terms used across the Pitangus documentation and panel, in alphabetical order. Each entry links to the page where
the term matters most.

## A

**Accepted risk.** A triage decision: the team knows about a finding and decides not to fix it for now. Only an
administrator can accept a risk, with a reason and an expiry date; when it expires, the finding counts again. See
[Findings](findings.md).

**Active scan.** A dynamic test that sends attacks (injections, fuzzing, crafted payloads) to see whether an
application breaks. Pitangus doesn't run active scans; they are in development. See [Key concepts](concepts.md).

**Asset.** Something Pitangus scans and keeps a findings register for: a repository, a container image or a verified
domain. See [Key concepts](concepts.md).

## C

**CRA (Cyber Resilience Act).** The EU regulation on products with digital elements. It asks manufacturers for an
SBOM and to report actively exploited vulnerabilities within set deadlines. Pitangus has an opt-in CRA kit. See
[Compliance](compliance.md).

**CVE (Common Vulnerabilities and Exposures).** The public identifier of a known vulnerability, such as
`CVE-2024-3094`. Pitangus keeps a local copy of NVD's CVE records in the **CVE tracker**. See [Findings](findings.md).

**CVSS (Common Vulnerability Scoring System).** A 0–10 score of a vulnerability's technical severity, computed from a
vector. Pitangus computes the score from the vector rather than copying it. It says how bad a flaw is, not how likely
it is to be exploited (see EPSS and KEV).

**CWE (Common Weakness Enumeration).** A catalog of kinds of weakness, such as CWE-79 (cross-site scripting). Findings
carry their CWE, which links them to OWASP guidance and to threats in a threat model.

## D

**DAST (dynamic application security testing).** Testing a running application from the outside, through its
responses. Pitangus's DAST is passive. See [Scan a website or API](scanning-web.md).

**Domain verification.** Proving to Pitangus that you control a domain before it can be scanned, with a DNS TXT
record, a file under `/.well-known/` or a meta tag. Only a DNS proof covers subdomains. It proves control, not
authorization to test. See [Scan a website or API](scanning-web.md).

**Due date.** The date by which a pending finding should be fixed, counted from its first detection by severity
(by default: critical 7 days, high 30, medium 90, low 180). See [Findings](findings.md).

## E

**Egress IP.** The public address the server's scans leave from. If a site filters by IP (a firewall or WAF), it
must allow this address. Set it with `PITANGUS_EGRESS_IPS`. See [Scan a website or API](scanning-web.md).

**EPSS (Exploit Prediction Scoring System).** A daily probability, from FIRST, that a CVE will be exploited in the
next 30 days. Pitangus downloads the whole feed and uses it for priority.

**Excluded path.** A folder or pattern an administrator excludes from a repository's findings (test fixtures,
generated code), with a reason. Excluded findings don't count or block PRs, but stay visible. See
[Findings](findings.md).

## F

**False positive.** A triage decision: the tool reported something that isn't a real problem. It needs a reason and
stays in the finding's history. See [Findings](findings.md).

**Finding.** One possible problem at one place, reported by a tool: a vulnerable package, a secret on a line, a
misconfiguration, a missing header at a URL. See [Key concepts](concepts.md).

**Fingerprint.** A finding's stable identifier, computed from what the problem is and where, never from a secret's
value. It lets Pitangus recognize the same finding across runs. See [Key concepts](concepts.md).

## G

**GHSA (GitHub Security Advisory).** An advisory in GitHub's Advisory Database, with an identifier like
`GHSA-xxxx-xxxx-xxxx`. Often the same vulnerability as a CVE; Pitangus merges them into one finding.

## I

**IaC (infrastructure as code).** Infrastructure described in files: Terraform, Kubernetes manifests, Dockerfiles,
CloudFormation, pipelines. Pitangus checks it with Trivy and zizmor, and with Checkov too when it's turned on. See [Scan your code](scanning-code.md).

## K

**KEV (Known Exploited Vulnerabilities).** CISA's catalog of vulnerabilities exploited in the wild. A finding in KEV
goes to the top of the priorities. See [Findings](findings.md).

## N

**Not tested.** The status of a step whose engine didn't run (Docker unreachable, an image missing, an option off).
Nothing is claimed about what that engine checks. See [Key concepts](concepts.md).

## O

**OSV (Open Source Vulnerabilities).** An open database of advisories for open-source packages, which also includes
GitHub's advisories. OSV-Scanner compares your dependencies against it locally.

**OWASP Top 10.** The OWASP Foundation's list of the ten most important categories of web application risk (current
edition: 2025). Findings link to their category, and the **Coverage** page maps scans to it. See
[Findings](findings.md).

## P

**Partial coverage.** Part of what a scan was supposed to look at wasn't looked at (a tool failed, a host wasn't
reached, a test user couldn't sign in). Few findings in that part prove nothing, and earlier findings there aren't
marked fixed. See [Key concepts](concepts.md).

**Passive scan.** A dynamic test that only sends what an ordinary visitor would and reads the answers. Pitangus's web
scans are passive. See [Scan a website or API](scanning-web.md).

**Pentest (penetration test).** A test where a person or an agent tries to exploit flaws in a running system and
demonstrates the impact. Pitangus does analysis, not pentests. See [Key concepts](concepts.md).

**PR review.** A scan of a pull request's head commit that counts only what the PR introduces, with a comment and a
commit status on GitHub that can block the merge. See [Scan your code](scanning-code.md).

## R

**Run.** The record of one scan, PR review, import or advisory check: what was analyzed, its steps and their statuses,
its findings and its limitations. See [Key concepts](concepts.md).

## S

**SARIF (Static Analysis Results Interchange Format).** A standard JSON format for scanner results (version 2.1.0).
Pitangus exports it and imports it from other tools. See [Integrations and automation](integrations.md).

**SAST (static application security testing).** Analyzing source code without running it, looking for flaws such as
injections. Pitangus runs Opengrep with its own rules. See [Scan your code](scanning-code.md).

**SBOM (software bill of materials).** The list of components a piece of software contains, with versions and
licenses. Pitangus exports CycloneDX 1.6. See [Compliance](compliance.md).

**SCA (software composition analysis).** Checking your dependencies against known vulnerabilities. See
[Scan your code](scanning-code.md).

**Scope.** The hosts a web scan may reach: the domain itself, plus any subdomains an administrator marks
**Analyze** in the domain's **Scope** tab. Anything outside it isn't requested. See
[Scan a website or API](scanning-web.md).

**Secret.** A credential in code or an image: an API key, a token, a password, a private key. Pitangus reports where
it is, never its value.

**STRIDE.** A threat-modeling method that looks for six kinds of threat: Spoofing, Tampering, Repudiation, Information
disclosure, Denial of service and Elevation of privilege. See [Threat modeling](threat-modeling.md).

## T

**Test user.** An account on your own site that a web scan signs in as, to look at pages behind a login. Saved per
domain, encrypted, with an optional TOTP key. See [Scan a website or API](scanning-web.md).

**Threat model.** A description of a system (components, data flows, trust boundaries) and the threats against it.
See [Threat modeling](threat-modeling.md).

**TOTP (time-based one-time password).** The six-digit codes of an authenticator app. Required for Pitangus
administrators, and supported for test users whose sign-in asks for one.

**Triage.** Recording a decision about a finding: in progress, false positive, accepted risk or fixed. See
[Findings](findings.md).

## V

**Verify again.** Rescanning after a fix to confirm it landed. In the panel, **Reverify** on a finding answers
**Fixed ✓** or **Still present**. See [Findings](findings.md).

**VEX (Vulnerability Exploitability eXchange).** Machine-readable statements about whether a product is affected by a
vulnerability. Pitangus turns triage into OpenVEX. See [Compliance](compliance.md).

## W

**Worker.** The process that runs scans, one at a time, taken from a queue in PostgreSQL. Add workers to scan more at
once. See [Scaling](scaling.md).

**WSTG (Web Security Testing Guide).** OWASP's guide to testing web applications, with a numbered test per topic.
Web findings link to the WSTG test that fits.
