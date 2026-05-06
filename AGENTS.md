# AGENTS.md

This file provides guidance to AI agents when working with code in this
repository.

## Commands

Dependencies are managed with Poetry. Prefix commands with `poetry run` (or
activate the venv).

- `poetry install` — set up the dev environment
- `poetry run make test` — run pytest
- `poetry run pytest tests/test_firewall.py::TestClass::test_name` — run a
  single test
- `poetry run make lint` — flake8 over `panos` and `tests`
- `poetry run make check-format` / `make format` — check / apply black + isort
- `poetry run make bandit` — security scan
- `poetry run make test-all` — run the full tox matrix

## Architecture

`pan-os-python` is an object-oriented SDK that mirrors the PAN-OS configuration
tree. Users build a tree of objects rooted at a device, then call CRUD methods
that translate to XML API calls against a firewall or Panorama.

Core abstractions live in `panos/base.py`:

- `PanObject` — base node. Every config object has an `XPATH`, optional `SUFFIX`
  (`ENTRY`/`MEMBER`), a `ROOT` (DEVICE / VSYS / PANORAMA / …), and a
  `CHILDTYPES` tuple declaring which classes may be added under it. `add()` /
  `remove()` / `find()` build and traverse the tree; `xpath()` is composed by
  walking parents up to the `PanDevice` at the root.
- `VersionedPanObject` — subclass used for almost all real config objects.
  Parameters are declared via `_setup()` using `VersionedParamPath` entries,
  each with per-PAN-OS-version XML paths. The object renders different XML
  depending on the connected device's version.
- `VsysOperations` — mixin behavior for objects that live inside a vsys and need
  import/export handling.
- `PanDevice` — base for `firewall.Firewall` and `panorama.Panorama`. Owns the
  `pan.xapi` connection, version detection, HA state, commit/op helpers, and is
  always the root of the tree.

Module layout follows the PAN-OS config hierarchy: `device.py`, `network.py`,
`objects.py`, `policies.py`, `ha.py`, `panorama.py`, `predefined.py`,
`plugins.py`, `userid.py`, `updater.py`, `errors.py`. Adding a new config node
usually means subclassing `VersionedPanObject` (or `VsysOperations`) in the
right module, defining `_setup()`, and adding it to the parent's `CHILDTYPES`.

Tests under `tests/` are mostly offline unit tests that mock `pan.xapi`;
`tests/live/` and `test_integration.py` hit real devices and aren't run by
default.

## Releases & commit style

This repo uses semantic-release driven by Conventional Commits (`feat:`, `fix:`,
`chore:`, …). Commit messages determine version bumps and changelog entries —
keep the prefix correct.
