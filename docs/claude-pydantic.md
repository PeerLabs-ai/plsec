## Validation and Type Discipline

### Pydantic: Boundaries Only

Use Pydantic models exclusively at system boundaries:

- Ingestion of external data (API requests, survey responses, file uploads)
- Configuration loading (settings, instrument definitions, report templates)
- Data exchange contracts with external systems

Do NOT use Pydantic for:

- Internal data transfer between functions or services
- Domain objects already validated at the boundary
- View-to-template data passing
- Wrapping Django model instances

Once data crosses a trust boundary and enters the domain, use plain Python: dataclasses, typed dicts, or Django model instances. Do not re-validate internally.

### No Framework Magic in Domain Logic

Prefer explicit, debuggable code over implicit framework behaviour:

- No metaclass-driven DSLs in business logic
- No decorator-based validation pipelines where a `__post_init__` or plain function will do
- No serialization aliases, computed fields, or `model_config` overrides unless the boundary contract genuinely requires them
- If a behaviour cannot be understood by reading the code top to bottom, refactor until it can

Django's ORM magic is accepted at the persistence layer. Pydantic's magic is accepted at ingestion boundaries. Neither should leak into domain logic.

### Validation Layering

This project uses Django's native validation stack internally:

- Django model field types and validators for persistence constraints
- Django forms or DRF serializers for API-layer validation
- Pydantic only where Django's tools are insufficient (deeply nested schemas, complex conditional validation at ingestion)

Do not create parallel validation hierarchies. One validation layer per boundary, not three.
