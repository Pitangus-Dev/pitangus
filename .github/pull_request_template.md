> **Don't paste tokens, keys, `.pem` files or unreviewed logs.** For security issues, use *Security → Report a vulnerability*.

**What it changes and why**

**How it was tested**

**Checklist** ([CONTRIBUTING.md](https://github.com/Tamandua-AppSec/tamandua/blob/main/.github/CONTRIBUTING.md))
- [ ] `make check` passes
- [ ] If it touches `web/src`: `make web` rebuilt `tamandua/app/static`
- [ ] If it changes a route or an API schema: `make openapi`
- [ ] Text people read is in the English and Spanish catalogs; docs updated in `docs/` and `docs/es/`
- [ ] Anything that couldn't be tested is said so, here and in the code (`not_tested` with a reason)
- [ ] Behaviour changes are noted under *Unreleased* in [CHANGELOG.md](https://github.com/Tamandua-AppSec/tamandua/blob/main/CHANGELOG.md)
