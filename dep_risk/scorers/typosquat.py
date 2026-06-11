from __future__ import annotations

import re
from typing import Any, Optional

from dep_risk.scorers.base import Dependency, RiskScore

TOP_NPM_PACKAGES: frozenset[str] = frozenset([
    "lodash", "chalk", "commander", "react", "express", "moment", "axios", "bluebird",
    "webpack", "babel-core", "eslint", "typescript", "jest", "mocha", "underscore",
    "jquery", "angular", "vue", "next", "nuxt", "gatsby", "svelte", "ember",
    "request", "superagent", "node-fetch", "got", "cross-fetch", "isomorphic-fetch",
    "async", "q", "rxjs", "redux", "mobx", "zustand", "recoil", "jotai",
    "mongodb", "mongoose", "sequelize", "knex", "typeorm", "prisma",
    "socket.io", "ws", "uuid", "semver", "yargs", "minimist", "dotenv",
    "debug", "winston", "morgan", "helmet", "cors", "body-parser", "multer",
    "passport", "jsonwebtoken", "bcrypt", "bcryptjs", "crypto-js", "node-rsa",
    "mysql", "mysql2", "pg", "redis", "ioredis", "elasticsearch",
    "prettier", "husky", "lint-staged", "nodemon", "ts-node", "concurrently",
    "react-dom", "react-router", "react-router-dom", "react-redux", "react-query",
    "@babel/core", "@babel/preset-env", "@babel/preset-react",
    "@testing-library/react", "@types/node", "@types/react",
    "dayjs", "date-fns", "luxon", "classnames", "clsx",
    "immer", "lodash-es", "ramda", "fp-ts",
    "zod", "yup", "joi", "ajv", "validator",
    "cheerio", "puppeteer", "playwright", "selenium-webdriver",
    "sharp", "jimp", "canvas", "three",
    "d3", "chart.js", "recharts", "victory",
    "tailwindcss", "sass", "less", "styled-components", "emotion",
    "webpack-cli", "webpack-dev-server", "vite", "rollup", "parcel", "esbuild",
    "babel-loader", "css-loader", "style-loader", "file-loader",
    "core-js", "regenerator-runtime", "tslib",
    "mime", "mime-types", "accepts", "negotiator",
    "path", "fs-extra", "glob", "chokidar", "rimraf", "mkdirp",
    "open", "execa", "cross-env", "which", "find-up",
    "tar", "archiver", "jszip", "adm-zip",
    "xml2js", "cheerio", "htmlparser2", "marked", "showdown", "remarkable",
    "sprintf-js", "printf", "numeral", "accounting",
    "events", "eventemitter3", "mitt",
    "node-cache", "lru-cache", "memory-cache",
    "config", "nconf", "convict",
    "cron", "node-cron", "agenda", "bull", "bee-queue",
    "nodemailer", "sendgrid", "mailgun-js",
    "stripe", "paypal-rest-sdk", "braintree",
    "aws-sdk", "googleapis", "firebase", "supabase",
    "twilio", "vonage", "nexmo",
    "swagger-ui-express", "swagger-jsdoc", "express-openapi",
    "express-validator", "celebrate", "fastest-validator",
    "compression", "serve-static", "serve-favicon",
    "cookie-parser", "cookie-session", "express-session",
    "method-override", "connect-flash", "passport-local",
    "graphql", "apollo-server", "type-graphql",
    "jest-circus", "jasmine", "ava", "tape", "sinon", "nock",
    "supertest", "chai", "should", "expect",
    "nyc", "istanbul", "c8",
    "tslint", "eslint-config-airbnb", "eslint-plugin-react",
    "standard", "xo",
    "pm2", "forever", "cluster", "throng",
    "csurf", "express-rate-limit", "hpp", "xss-clean",
    "multer", "formidable", "busboy",
    "i18next", "react-i18next", "intl",
    "lodash.debounce", "lodash.throttle", "lodash.merge", "lodash.get", "lodash.set",
    "string-width", "strip-ansi", "ansi-regex", "supports-color",
    "minimatch", "micromatch", "picomatch",
    "resolve", "enhanced-resolve", "module-alias",
    "source-map", "source-map-support",
    "throat", "p-limit", "p-queue", "p-map",
    "object-assign", "inherits", "util-deprecate",
    "once", "end-of-stream", "pump", "through2", "bl",
    "isarray", "is-buffer", "is-plain-object",
    "ansi-styles", "color-convert", "color-name",
    "readable-stream", "safe-buffer",
    "qs", "querystring", "qs",
    "ms", "bytes", "filesize",
    "ip", "ipaddr.js", "netmask",
    "base64-js", "ieee754", "buffer",
    "graceful-fs", "iconv-lite", "encoding",
])

TOP_PIP_PACKAGES: frozenset[str] = frozenset([
    "requests", "numpy", "pandas", "scipy", "matplotlib", "scikit-learn",
    "tensorflow", "torch", "keras", "flask", "django", "fastapi", "aiohttp",
    "sqlalchemy", "celery", "redis", "boto3", "botocore", "s3transfer",
    "pydantic", "attrs", "click", "rich", "typer", "tqdm",
    "pillow", "opencv-python", "opencv-contrib-python",
    "pytest", "unittest2", "coverage", "mock", "faker",
    "cryptography", "pyopenssl", "paramiko", "pycryptodome",
    "beautifulsoup4", "lxml", "html5lib", "scrapy",
    "httpx", "urllib3", "certifi", "charset-normalizer",
    "setuptools", "wheel", "pip", "twine", "build",
    "black", "isort", "flake8", "pylint", "mypy", "pyflakes",
    "ipython", "jupyter", "notebook", "jupyterlab",
    "yaml", "toml", "dotenv", "python-dotenv", "decouple",
    "arrow", "pendulum", "dateutil", "python-dateutil",
    "jinja2", "mako", "chameleon",
    "pymongo", "motor", "elasticsearch", "redis",
    "psycopg2", "psycopg2-binary", "asyncpg", "aiomysql",
    "sqlparse", "alembic", "peewee",
    "gunicorn", "uvicorn", "hypercorn", "daphne",
    "pika", "aio-pika", "kafka-python", "confluent-kafka",
    "grpcio", "protobuf", "thrift",
    "jsonschema", "marshmallow", "cerberus", "voluptuous",
    "loguru", "structlog", "python-json-logger",
    "apscheduler", "schedule", "rq", "dramatiq",
    "parameterized", "hypothesis",
    "docutils", "sphinx", "mkdocs",
    "pytz", "tzlocal", "babel",
    "six", "future", "past",
    "packaging", "distlib", "platformdirs",
    "more-itertools", "toolz", "cytoolz", "boltons",
    "tabulate", "prettytable", "termcolor", "colorama",
    "argparse", "docopt", "fire",
    "cachetools", "diskcache", "joblib",
    "regex", "parsimonious", "pyparsing",
    "multiprocess", "pathos", "dask", "ray",
    "networkx", "graphviz",
    "shapely", "pyproj", "geopandas",
    "nltk", "spacy", "gensim", "transformers", "datasets",
    "sympy", "mpmath",
    "pymysql", "cx-oracle", "pyodbc", "sqlite3",
    "ldap3", "python-ldap",
    "docker", "kubernetes", "ansible",
    "fabric", "invoke", "sh", "plumbum",
    "prometheus-client", "statsd", "datadog",
    "sentry-sdk", "rollbar",
    "stripe", "twilio", "sendgrid",
    "google-cloud-storage", "google-cloud-bigquery", "google-auth",
    "azure-storage-blob", "azure-identity", "msrest",
    "httplib2", "oauth2client", "google-api-python-client",
    "pyserial", "pyusb", "bluetooth",
    "pytest-django", "pytest-asyncio", "pytest-mock", "pytest-cov",
    "freezegun", "responses", "vcrpy",
    "pyyaml", "ruamel.yaml",
    "tomlkit", "tomli", "tomllib",
    "chardet", "idna",
    "wrapt", "decorator", "functools32",
    "werkzeug", "itsdangerous", "markupsafe",
    "starlette", "anyio", "trio", "asyncio",
    "uvloop", "gevent", "eventlet",
    "watchdog", "watchfiles",
    "dynaconf", "decouple", "environs",
    "humanize", "inflect",
    "psutil", "py-cpuinfo", "gputil",
])

TOP_CARGO_PACKAGES: frozenset[str] = frozenset([
    "serde", "serde_json", "tokio", "async-std", "futures", "futures-util",
    "rand", "rand_core", "chrono", "clap", "log", "env_logger", "tracing",
    "anyhow", "thiserror", "color-eyre",
    "reqwest", "hyper", "axum", "actix-web", "warp", "rocket",
    "sqlx", "diesel", "sea-orm",
    "rayon", "crossbeam", "parking_lot", "dashmap",
    "itertools", "once_cell", "lazy_static",
    "regex", "url", "uuid", "semver",
    "bytes", "encoding_rs", "flate2", "zip",
    "toml", "serde_yaml", "csv", "xml",
    "rusqlite", "redis", "mongodb", "postgres",
    "openssl", "ring", "rustls", "native-tls",
    "bcrypt", "argon2", "sha2", "hmac",
    "base64", "hex", "percent-encoding",
    "tower", "tower-http", "hyper-util",
    "tempfile", "walkdir", "glob", "path",
    "clap_derive", "structopt", "argh",
    "indicatif", "console", "colored", "termcolor",
    "config", "dotenv", "envy",
    "criterion", "proptest", "quickcheck",
    "mockall", "mockito", "httpmock",
    "serde_with", "indexmap", "hashbrown",
    "num", "num-traits", "num-integer", "num-bigint",
    "image", "imageproc",
    "nalgebra", "ndarray", "linfa",
    "pyo3", "neon", "wasm-bindgen",
    "winapi", "windows", "nix",
    "libc", "memchr", "smallvec", "arrayvec",
    "derive_more", "strum", "bitflags",
    "pin-project", "pin-project-lite",
    "ahash", "fnv", "fxhash",
    "parking_lot", "spin",
    "async-trait", "async-recursion",
    "tokio-util", "tokio-stream",
    "tonic", "prost",
    "jsonwebtoken", "oauth2",
    "lettre", "ureq", "attohttpc",
    "tracing-subscriber", "tracing-bunyan-formatter",
    "slog", "slog-term",
    "metrics", "prometheus",
    "arrow", "polars", "datafusion",
    "tantivy", "meilisearch-sdk",
    "rustfmt-nightly", "clippy",
    "cargo-edit", "cargo-audit", "cargo-outdated",
    "bindgen", "cc", "pkg-config",
    "gimli", "object", "addr2line",
    "wasmtime", "wasmer",
    "crossterm", "tui", "ratatui",
    "serde_cbor", "bincode", "rmp-serde",
    "aes", "chacha20", "ed25519-dalek",
    "zstd", "lz4", "snappy",
])

_ECOSYSTEM_TOP: dict[str, frozenset[str]] = {
    "npm": TOP_NPM_PACKAGES,
    "pip": TOP_PIP_PACKAGES,
    "cargo": TOP_CARGO_PACKAGES,
}

_HOMOGLYPHS: dict[str, list[str]] = {
    "l": ["1", "I"],
    "1": ["l", "I"],
    "I": ["l", "1"],
    "O": ["0"],
    "0": ["O"],
    "rn": ["m"],
    "m": ["rn"],
    "vv": ["w"],
    "w": ["vv"],
    "cl": ["d"],
    "d": ["cl"],
}


def _damerau_levenshtein(s1: str, s2: str) -> int:
    len1, len2 = len(s1), len(s2)
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1
    if abs(len1 - len2) > 3:
        return abs(len1 - len2)

    d: list[list[int]] = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(len1 + 1):
        d[i][0] = i
    for j in range(len2 + 1):
        d[0][j] = j

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,
                d[i][j - 1] + 1,
                d[i - 1][j - 1] + cost,
            )
            if i > 1 and j > 1 and s1[i - 1] == s2[j - 2] and s1[i - 2] == s2[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)
    return d[len1][len2]


def _has_homoglyph(name: str, popular: str) -> bool:
    for char, replacements in _HOMOGLYPHS.items():
        for rep in replacements:
            if name.replace(char, rep) == popular or popular.replace(char, rep) == name:
                return True
    return False


def _normalize(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "").replace(".", "")


class TyposquatScorer:
    name = "typosquat"
    weight = 0.20

    async def score(
        self,
        dep: Dependency,
        registry_data: Any,
        github_data: Any,
    ) -> RiskScore:
        ecosystem = dep.ecosystem
        top_packages = _ECOSYSTEM_TOP.get(ecosystem, frozenset())
        name = dep.name.lower()

        if name in top_packages:
            return RiskScore(
                scorer=self.name,
                score=0.0,
                weight=self.weight,
                finding="Package is in top popular list — not a typosquat",
                detail="This package appears in the curated top packages list.",
                evidence={"in_top_list": True},
            )

        score = 0.0
        findings: list[str] = []
        details: list[str] = []
        evidence: dict[str, Any] = {"closest_matches": []}

        norm_name = _normalize(name)
        best_dist = 999
        best_match: Optional[str] = None

        for popular in top_packages:
            if _has_homoglyph(name, popular):
                score += 80
                findings.append(f"Homoglyph substitution detected — similar to '{popular}'")
                details.append(f"Name '{name}' uses characters visually similar to '{popular}'")
                evidence["homoglyph_of"] = popular
                best_dist = 0
                best_match = popular
                break

            norm_popular = _normalize(popular)
            dist = _damerau_levenshtein(norm_name, norm_popular)
            if dist < best_dist:
                best_dist = dist
                best_match = popular

            if dist == 1:
                score += 70
                findings.append(f"Possible typosquat of '{popular}' (edit distance 1)")
                details.append(f"Package name differs by 1 character from popular package '{popular}'")
                evidence["typosquat_of"] = popular
                evidence["edit_distance"] = 1
                break

        if not findings and best_dist == 2 and best_match:
            score += 35
            findings.append(f"Similar name to '{best_match}' (edit distance 2)")
            details.append(f"Package name is 2 edits away from '{best_match}'")
            evidence["similar_to"] = best_match
            evidence["edit_distance"] = 2

        if not findings:
            clean = re.sub(r"[-_.]", "", name)
            for popular in top_packages:
                clean_popular = re.sub(r"[-_.]", "", popular.lower())
                if clean == clean_popular + "s" or clean + "s" == clean_popular:
                    score += 35
                    findings.append(f"Pluralization typosquat of '{popular}'")
                    details.append(f"'{name}' appears to be a pluralized version of '{popular}'")
                    evidence["pluralization_of"] = popular
                    break
                if clean == clean_popular.replace("-", "") + "2" or clean == clean_popular + "3":
                    score += 25
                    findings.append(f"Numbered variant of '{popular}'")
                    details.append(f"'{name}' appears to be a numbered variant of '{popular}'")
                    evidence["numbered_variant_of"] = popular
                    break

        score = min(100.0, score)
        finding = findings[0] if findings else f"No typosquat detected (closest: '{best_match}', dist={best_dist})"
        detail = "\n".join(details) if details else "Package name does not resemble popular packages."

        return RiskScore(
            scorer=self.name,
            score=score,
            weight=self.weight,
            finding=finding,
            detail=detail,
            evidence=evidence,
        )
