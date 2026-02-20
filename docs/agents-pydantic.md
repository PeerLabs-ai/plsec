## Validation, Typing, and Framework Magic

### Guiding Principles

1. **Pydantic at the boundaries, plain Python in the interior.** External data is untrusted and benefits from structured validation. Internal data has already been validated and should flow through the system without redundant ceremony.

2. **No magic except where it earns its keep.** Metaclass machinery, implicit pipelines, decorator-driven execution ordering, and runtime code generation trade debuggability for expressiveness. Accept this trade only at well-defined boundaries (ORM, ingestion, serialization) and refuse it in domain logic.

3. **One validation layer per boundary.** Do not stack Pydantic on top of DRF serializers on top of Django model validators for the same data path. Choose the tool appropriate to the boundary and use it alone.

4. **If you cannot debug it with a breakpoint and a top-to-bottom read, refactor it.** Validator chains with `mode='before'`/`mode='after'`/`mode='wrap'` ordering, serialization aliases, and computed fields create implicit execution models. Prefer explicit `__post_init__` methods or plain validation functions wherever possible.

### Pydantic Usage Rules

**Allowed at:**
- API ingestion boundaries (request parsing, file upload validation)
- Configuration and schema loading (instrument definitions, report templates, settings)
- External system integration contracts

**Not allowed for:**
- Internal DTOs or service-layer data passing
- Wrapping Django model instances or querysets
- Domain logic, analytics, or report generation internals
- Any context where a dataclass, TypedDict, or plain function signature suffices

### Rationale

This project values transparency and debuggability over framework convenience. Python's strength is readability; abstractions that obscure execution flow undermine this strength. When validation complexity grows beyond what Django's native tools handle cleanly -- deeply nested schemas, conditional cross-field validation at ingestion -- Pydantic is the right tool. Everywhere else, it is unnecessary indirection.

We do not want to reproduce the enterprise Java pattern of proliferating model classes (`FooDTO`, `FooRequest`, `FooResponse`, `FooEntity`) representing the same data at different abstraction layers. If you find yourself creating a Pydantic model mirroring a Django model, stop and ask whether the Django model or a DRF serializer already covers the need.
