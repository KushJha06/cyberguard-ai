# CyberGuard example plugin

Copy this directory outside the core repository, rename the package and rule IDs, add tests, then install it into the same environment as CyberGuard:

```bash
pip install -e .
```

Restart the API and confirm the plugin appears in **Integrations & Plugins** or `GET /api/v1/plugins`.
