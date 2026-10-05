# indexnow-ping

Submits URLs to [IndexNow](https://www.indexnow.org/) after a GitHub Pages or static site deploy, so participating search engines learn about changed pages without waiting for a crawl. URLs come from a sitemap (sitemap index files are followed one level deep, gzip handled, with a `changed-since` filter on `<lastmod>`) or from an explicit list. Requests are batched at the IndexNow limit of 10,000 URLs, sent with a bounded timeout, and a 429 answer is retried once. No dependencies; Node 18 or later.

## Usage

Run it after the deploy job and let it fail without failing the deploy:

```yaml
jobs:
  deploy:
    # ... your Pages deploy job ...
  indexnow:
    needs: deploy
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: basitalisandhu/security-actions/indexnow-ping@v0
        continue-on-error: true   # a search engine outage should not turn the deploy red
        with:
          host: www.example.org
          key: ${{ secrets.INDEXNOW_KEY }}
          sitemap-url: https://www.example.org/sitemap.xml
          changed-since: 24h
```

Explicit URLs, for example from a changed-files step:

```yaml
      - uses: basitalisandhu/security-actions/indexnow-ping@v0
        continue-on-error: true
        with:
          host: www.example.org
          key: ${{ secrets.INDEXNOW_KEY }}
          urls: |
            https://www.example.org/blog/new-post/
            https://www.example.org/blog/
```

Set up the key once: generate a key (8 to 128 characters from `a-z`, `A-Z`, `0-9` and `-`), publish it as `https://www.example.org/<key>.txt` containing the key, and store the key as a repository secret or variable. The key is not a credential in the usual sense (it is public on your site) but keeping it in a secret avoids editing workflows when it rotates. Use `key-location` when the file lives elsewhere on the host.

## Inputs

| Input | Default | Description |
|---|---|---|
| `host` | required | Host the URLs belong to. URLs on other hosts are skipped and counted. |
| `key` | `""` | IndexNow key. Required unless `dry-run` is `"true"`. |
| `key-location` | `""` | URL of the key file when it is not at `https://host/<key>.txt`. |
| `sitemap-url` | `""` | Sitemap or sitemap index URL. |
| `urls` | `""` | Explicit URLs, one per line; always submitted. |
| `urls-file` | `""` | File with one URL per line. |
| `changed-since` | `""` | ISO 8601 date or duration (`24h`, `7d`). Sitemap entries without `lastmod` are skipped when set. |
| `endpoint` | `https://api.indexnow.org/indexnow` | Endpoint; the default shares submissions with every participating engine. |
| `max-urls` | `10000` | Upper bound on URLs submitted per run. |
| `timeout` | `30` | Seconds per HTTP request. |
| `dry-run` | `"false"` | List the selected URLs without sending anything. |
| `node-version` | `""` | Set up this Node version first; empty uses the runner's `node`. |

## Outputs

| Output | Description |
|---|---|
| `url-count` | URLs selected. |
| `submitted-count` | URLs the endpoint accepted (200 or 202). |
| `status-code` | Status of the last request; empty on a dry run. |
| `skipped-count` | URLs skipped for host, `lastmod` or parse reasons. |

## Status codes

| Code | Meaning | Exit |
|---|---|---|
| 200 | URLs submitted | 0 |
| 202 | Accepted, key validation pending | 0 |
| 400 | Bad request | 1 |
| 403 | Key not valid (not found at the key location) | 1 |
| 422 | URLs do not belong to the host, or key does not match the schema | 1 |
| 429 | Too many requests; retried once after `Retry-After` | 1 if it persists |

## Permissions

None. The action needs no GitHub token; it only talks to the sitemap host and the IndexNow endpoint.

## Local use

```sh
INPUT_HOST=www.example.org INPUT_KEY=... INPUT_SITEMAP_URL=https://www.example.org/sitemap.xml INPUT_DRY_RUN=true node indexnow-ping/src/indexnow.mjs
node --test "indexnow-ping/tests/*.test.mjs"
```
