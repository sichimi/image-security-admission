"""Shared reviewed-allowlist enforcement, not a scanner/signature verifier.

All criteria come from this action's pinned policy.json. Caller files declare
inputs and reviewed evidence summaries; they cannot replace the criteria.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import shlex

ACTION = Path(__file__).resolve().parent
SHA = re.compile(r"[0-9a-f]{64}")
REF = re.compile(r"[a-z0-9.-]+\.[a-z]+(?::\d+)?/[a-z0-9._/-]+(?::[a-zA-Z0-9_.-]+)?@sha256:[0-9a-f]{64}")
CONFIG_KEYS = {"schemaVersion", "platform", "dockerfile", "stages", "approvedImages"}


class AdmissionError(ValueError):
    pass


def require(value, code):
    if not value:
        raise AdmissionError(code)


def read_local(root, relative):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute(), "RELATIVE_INPUT_REQUIRED")
    root = Path(root).resolve()
    path = (root / relative).resolve()
    require(path.is_relative_to(root) and path.is_file(), "INPUT_OUTSIDE_REPOSITORY_OR_MISSING")
    require(path.stat().st_size <= 1024 * 1024, "INPUT_TOO_LARGE")
    return path.read_text()


def fresh(value, now, policy):
    require(isinstance(value, str), "EVIDENCE_TIME_REQUIRED")
    try:
        timestamp = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(timestamp.tzinfo is not None, "EVIDENCE_TIMEZONE_REQUIRED")
        age = now - timestamp
    except (ValueError, TypeError):
        raise AdmissionError("EVIDENCE_TIME_INVALID") from None
    require(-dt.timedelta(minutes=policy["maxClockSkewMinutes"]) <= age
            <= dt.timedelta(hours=policy["maxEvidenceAgeHours"]), "EVIDENCE_EXPIRED_OR_FUTURE")


def runtime_floor(name, value, policy):
    require(name in policy["runtimeRules"], "RUNTIME_REQUIRES_CENTRAL_REVIEW")
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-r\d+)?", value or "")
    require(match is not None, "PACKAGE_VERSION_REQUIRED")
    actual = tuple(map(int, match.groups()))
    rule = policy["runtimeRules"][name]
    series = ".".join(map(str, actual[:rule["seriesLength"]]))
    minimum = rule["minimumBySeries"].get(series)
    require(minimum is not None and actual >= tuple(minimum), "CENTRAL_SECURITY_FLOOR_NOT_MET")


def image_inputs(dockerfile):
    require(not re.search(r"^\s*#\s*escape\s*=", dockerfile, re.M | re.I), "CUSTOM_ESCAPE_UNSUPPORTED")
    lines = dockerfile.splitlines()
    require(lines and re.fullmatch(r"#\s*syntax=(\S+)", lines[0], re.I), "FRONTEND_DIRECTIVE_MUST_BE_FIRST")
    syntax = re.findall(r"^\s*#\s*syntax\s*=\s*(\S+)\s*$", dockerfile, re.M | re.I)
    require(len(syntax) == 1, "EXPLICIT_FRONTEND_REQUIRED")
    stages, aliases = [], {}
    logical = re.sub(r"\\\r?\n", "", dockerfile)
    for line in logical.splitlines():
        if not re.match(r"^\s*FROM\s", line, re.I):
            continue
        fields = shlex.split(line, comments=True)[1:]
        if fields and fields[0].startswith("--platform="):
            require(fields[0] in {"--platform=$BUILDPLATFORM", "--platform=$TARGETPLATFORM"}, "STAGE_PLATFORM_UNSUPPORTED")
            fields = fields[1:]
        require(len(fields) == 1 or len(fields) == 3 and fields[1].upper() == "AS", "FROM_SYNTAX_UNSUPPORTED")
        image = aliases.get(fields[0], fields[0])
        stages.append(image)
        if len(fields) == 3:
            require(fields[2] not in aliases, "DUPLICATE_STAGE_ALIAS")
            aliases[fields[2]] = image
    require(stages, "EXTERNAL_STAGE_REQUIRED")
    internal = set(aliases) | {str(i) for i in range(len(stages))}
    for line in logical.splitlines():
        if not re.match(r"^\s*(COPY|ADD|RUN)\s", line, re.I):
            continue
        fields = shlex.split(line, comments=True)
        for field in fields[1:]:
            if fields[0].upper() in {"COPY", "ADD"} and field.startswith("--from"):
                require(field.startswith("--from=") and field.split("=", 1)[1] in internal, "EXTERNAL_COPY_IMAGE_UNREVIEWED")
            if fields[0].upper() == "RUN" and field.startswith("--mount"):
                require(field.startswith("--mount="), "MOUNT_SYNTAX_UNSUPPORTED")
                for option in field.split("=", 1)[1].split(","):
                    if option.startswith("from="):
                        require(option.split("=", 1)[1] in internal, "EXTERNAL_MOUNT_IMAGE_UNREVIEWED")
    return syntax[0], stages


def check_record(reference, role, runtimes, records, platform, policy, now):
    require(REF.fullmatch(reference), "IMMUTABLE_FULLY_QUALIFIED_REFERENCE_REQUIRED")
    matches = [r for r in records if r.get("reference") == reference and r.get("role") == role]
    require(len(matches) == 1, "REVIEWED_BASE_EVIDENCE_REQUIRED")
    record = matches[0]
    require(record.get("platform") == platform, "EVIDENCE_PLATFORM_MISMATCH")
    for key in ["checkedAt", "advisoryCheckedAt", "scanDatabaseUpdatedAt"]:
        fresh(record.get(key), now, policy)
    require(type(record.get("unresolvedFindings")) is int and record["unresolvedFindings"] == 0, "UNRESOLVED_FINDINGS")
    require(record.get("provenanceVerified") is True and record.get("compatibilityReviewed") is True, "VERIFICATION_INCOMPLETE")
    require(record.get("provenanceSubjectDigest") == reference.split("@", 1)[1], "PROVENANCE_SUBJECT_MISMATCH")
    require(isinstance(record.get("sourceRepository"), str) and record["sourceRepository"].startswith("https://"), "SOURCE_REQUIRED")
    require(re.fullmatch(r"[0-9a-f]{40}", record.get("sourceRevision", "")), "SOURCE_REVISION_REQUIRED")
    evidence = record.get("evidenceSha256", {})
    require(isinstance(evidence, dict) and all(isinstance(evidence.get(k), str) and SHA.fullmatch(evidence[k])
            for k in policy["requiredEvidenceHashes"]), "EVIDENCE_HASH_REQUIRED")
    observed = record.get("runtimes")
    require(isinstance(observed, dict) and set(observed) == set(runtimes), "RUNTIME_DECLARATION_MISMATCH")
    repository = reference.split("@", 1)[0]
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    required = policy["requiredRuntimesByRepository"].get(repository)
    require(required is not None or observed, "UNCLASSIFIED_IMAGE_RUNTIME_REQUIRED")
    require(set(required or []).issubset(observed), "KNOWN_RUNTIME_OMITTED")
    for name, value in observed.items():
        runtime_floor(name, value, policy)


def admit(dockerfile, config, policy, now):
    require(set(config) == CONFIG_KEYS, "CALLER_CONFIG_ONLY_NO_POLICY_OVERRIDES")
    require(type(config.get("schemaVersion")) is int and config["schemaVersion"] == 1, "CONFIG_SCHEMA_INVALID")
    platform = config.get("platform")
    require(platform in {"linux/amd64", "linux/arm64"}, "PLATFORM_UNSUPPORTED")
    records = config.get("approvedImages")
    require(isinstance(records, list) and all(isinstance(r, dict) for r in records), "ALLOWLIST_INVALID")
    keys = [(r.get("reference"), r.get("role")) for r in records]
    require(len(keys) == len(set(keys)), "DUPLICATE_APPROVAL")
    frontend, stages = image_inputs(dockerfile)
    declarations = config.get("stages")
    require(isinstance(declarations, dict) and set(declarations) == {str(i) for i in range(len(stages))}, "EVERY_STAGE_MUST_BE_DECLARED")
    check_record(frontend, "frontend", [], records, platform, policy, now)
    for i, reference in enumerate(stages):
        declaration = declarations[str(i)]
        require(isinstance(declaration, dict) and set(declaration) == {"role", "runtimes"}, "STAGE_CONFIG_INVALID")
        require(declaration["role"] in policy["roles"], "ROLE_UNSUPPORTED")
        names = declaration["runtimes"]
        require(isinstance(names, list) and all(isinstance(n, str) for n in names) and len(names) == len(set(names)), "RUNTIME_CONFIG_INVALID")
        check_record(reference, declaration["role"], names, records, platform, policy, now)
    return "SHARED_IMAGE_BASES_ADMITTED"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--requirements", required=True)
    args = parser.parse_args()
    try:
        policy = json.loads((ACTION / "policy.json").read_text())
        config = json.loads(read_local(args.root, args.requirements))
        dockerfile = read_local(args.root, config.get("dockerfile"))
        print(admit(dockerfile, config, policy, dt.datetime.now(dt.timezone.utc)))
    except AdmissionError as error:
        print(f"IMAGE_SECURITY_ADMISSION_BLOCKED: {error}")
        return 1
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        print("IMAGE_SECURITY_ADMISSION_BLOCKED: INVALID_INPUT_OR_EVIDENCE")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
